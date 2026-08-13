import json
import os
import sys
import urllib.parse
from dataclasses import dataclass

from git import Optional

from socketsecurity import USER_AGENT
from socketsecurity.core import log
from socketsecurity.core.classes import Comment
from socketsecurity.core.scm_comments import Comments
from socketsecurity.socketcli import CliClient


@dataclass
class GithubConfig:
    """Configuration from GitHub environment variables"""
    sha: str
    api_url: str
    ref_type: str
    event_name: str
    workspace: str
    repository: str
    ref_name: str
    default_branch: bool
    is_default_branch: bool
    pr_number: Optional[str]
    pr_name: Optional[str]
    commit_message: Optional[str]
    actor: str
    env: str
    token: str
    owner: str
    event_action: Optional[str]
    headers: dict

    @staticmethod
    def _repository_from_buildkite() -> tuple[str, str]:
        """Return ``(owner, repository)`` from Buildkite's Git repository URL."""
        repository_url = (
            # Comments and statuses belong to the pipeline/base repository,
            # not a contributor's fork from BUILDKITE_PULL_REQUEST_REPO.
            os.getenv("BUILDKITE_REPO")
            or os.getenv("BUILDKITE_PULL_REQUEST_REPO")
            or ""
        ).strip()
        if not repository_url:
            return "", ""

        if "://" in repository_url:
            repository_path = urllib.parse.urlparse(repository_url).path
        elif ":" in repository_url:
            # SCP-style SSH URL: git@github.com:owner/repository.git
            repository_path = repository_url.split(":", 1)[1]
        else:
            repository_path = repository_url
        parts = repository_path.strip("/").removesuffix(".git").split("/")
        if len(parts) < 2:
            return "", ""
        return parts[-2], parts[-1]

    @classmethod
    def from_env(cls, pr_number: Optional[str] = None) -> 'GithubConfig':
        """Create config from environment variables with optional overrides"""
        token = os.getenv('GH_API_TOKEN')
        if not token:
            log.error("Unable to get Github API Token from GH_API_TOKEN")
            sys.exit(2)
        
        is_buildkite = os.getenv("BUILDKITE") == "true"
        buildkite_pr = os.getenv("BUILDKITE_PULL_REQUEST")
        is_buildkite_pr = bool(
            is_buildkite
            and buildkite_pr
            and buildkite_pr.casefold() != "false"
        )

        # Use explicit/GitHub-compatible values first, then native Buildkite PR context.
        pr_number = pr_number or os.getenv('PR_NUMBER')
        if not pr_number and is_buildkite_pr:
            pr_number = buildkite_pr
        
        # Add debug logging
        sha = os.getenv('GITHUB_SHA') or (
            os.getenv("BUILDKITE_COMMIT", "") if is_buildkite else ""
        )
        log.debug(f"Loading GitHub integration SHA: {sha}")
        event_action = os.getenv('EVENT_ACTION', None)
        if not event_action:
            event_path = os.getenv('GITHUB_EVENT_PATH')
            if event_path and os.path.exists(event_path):
                with open(event_path, 'r') as f:
                    event = json.load(f)
                    event_action = event.get('action')
        if not event_action and is_buildkite_pr:
            # Buildkite provides the current PR state, not the originating
            # GitHub webhook action. A running PR build is equivalent to the
            # supported synchronize path for comment updates.
            event_action = "synchronize"
        repository = os.getenv('GITHUB_REPOSITORY', '')
        owner = os.getenv('GITHUB_REPOSITORY_OWNER', '')
        if '/' in repository:
            owner = repository.split('/')[0]
            repository = repository.split('/')[1]
        elif is_buildkite:
            buildkite_owner, buildkite_repository = cls._repository_from_buildkite()
            owner = owner or buildkite_owner
            repository = repository or buildkite_repository

        default_branch_env = os.getenv('DEFAULT_BRANCH')
        # Consider the variable truthy if it exists and isn't explicitly 'false'
        if default_branch_env is not None:
            is_default = default_branch_env.lower() != 'false'
        elif is_buildkite:
            # Require a branch name: comparing two unset variables would otherwise report
            # every build as the default branch and overwrite the repository's baseline.
            buildkite_branch = os.getenv("BUILDKITE_BRANCH")
            is_default = bool(
                not is_buildkite_pr
                and buildkite_branch
                and buildkite_branch == os.getenv("BUILDKITE_PIPELINE_DEFAULT_BRANCH")
            )
        else:
            is_default = False

        event_name = os.getenv('GITHUB_EVENT_NAME', '')
        if not event_name and is_buildkite:
            event_name = "pull_request" if is_buildkite_pr else "push"
        return cls(
            sha=sha,
            api_url=os.getenv('GITHUB_API_URL') or (
                "https://api.github.com" if is_buildkite else ""
            ),
            ref_type=os.getenv('GITHUB_REF_TYPE') or (
                "branch" if is_buildkite else ""
            ),
            event_name=event_name,
            workspace=os.getenv('GITHUB_WORKSPACE') or (
                os.getenv("BUILDKITE_BUILD_CHECKOUT_PATH", "") if is_buildkite else ""
            ),
            repository=repository,
            ref_name=os.getenv('GITHUB_REF_NAME') or (
                os.getenv("BUILDKITE_BRANCH", "") if is_buildkite else ""
            ),
            default_branch=is_default,
            is_default_branch=is_default,
            pr_number=pr_number,
            pr_name=os.getenv('PR_NAME'),
            commit_message=os.getenv('COMMIT_MESSAGE') or (
                os.getenv("BUILDKITE_MESSAGE") if is_buildkite else None
            ),
            actor=os.getenv('GITHUB_ACTOR') or (
                os.getenv("BUILDKITE_BUILD_CREATOR", "") if is_buildkite else ""
            ),
            env=os.getenv('GITHUB_ENV', ''),
            token=token,
            owner=owner,
            event_action=event_action,
            headers={
                'Authorization': f"Bearer {token}",
                'User-Agent': USER_AGENT,
                "accept": "application/json"
            }
        )


class Github:
    def __init__(self, client: CliClient, config: Optional[GithubConfig] = None):
        self.config = config or GithubConfig.from_env()
        self.client = client

        if not self.config.token:
            log.error("Unable to get Github API Token")
            sys.exit(2)

    def check_event_type(self) -> str:
        if self.config.event_name.lower() in ["push", "workflow_dispatch"]:
            if not self.config.pr_number:
                return "main"
            return "diff"
        elif self.config.event_name.lower() == "pull_request":
            if self.config.event_action and self.config.event_action.lower() in ['opened', 'synchronize']:
                return "diff"
            log.info(f"Pull Request Action {self.config.event_action} is not a supported type")
            sys.exit(0)
        elif self.config.event_name.lower() == "issue_comment":
            return "comment"

        log.error(f"Unknown event type {self.config.event_name}")
        sys.exit(0)

    def post_comment(self, body: str) -> None:
        path = f"repos/{self.config.owner}/{self.config.repository}/issues/{self.config.pr_number}/comments"
        payload = json.dumps({"body": body})
        self.client.request(
            path=path,
            payload=payload,
            method="POST",
            headers=self.config.headers,
            base_url=self.config.api_url
        )

    def update_comment(self, body: str, comment_id: str) -> None:
        path = f"repos/{self.config.owner}/{self.config.repository}/issues/comments/{comment_id}"
        payload = json.dumps({"body": body})
        self.client.request(
            path=path,
            payload=payload,
            method="PATCH",
            headers=self.config.headers,
            base_url=self.config.api_url
        )

    def write_new_env(self, name: str, content: str) -> None:
        with open(self.config.env, "a") as f:
            new_content = content.replace("\n", "\\n")
            f.write(f"{name}={new_content}")

    def get_comments_for_pr(self) -> dict:
        log.debug(f"Getting comments for Repo {self.config.repository} for PR {self.config.pr_number}")
        path = f"repos/{self.config.owner}/{self.config.repository}/issues/{self.config.pr_number}/comments"
        response = self.client.request(
            path=path,
            headers=self.config.headers,
            base_url=self.config.api_url
        )
        raw_comments = Comments.process_response(response)

        comments = {}
        if "error" not in raw_comments:
            for item in raw_comments:
                comment = Comment(**item)
                comments[comment.id] = comment
                comment.body_list = comment.body.split("\n")
        else:
            log.error(raw_comments)

        return Comments.check_for_socket_comments(comments)

    def add_socket_comments(
        self,
        security_comment: str,
        overview_comment: str,
        comments: dict,
        new_security_comment: bool = True,
        new_overview_comment: bool = True
    ) -> None:
        if new_overview_comment:
            log.debug("New Dependency Overview comment")
            if overview := comments.get("overview"):
                log.debug("Previous version of Dependency Overview, updating")
                self.update_comment(overview_comment, str(overview.id))
            else:
                log.debug("No previous version of Dependency Overview, posting")
                self.post_comment(overview_comment)

        if new_security_comment:
            log.debug("New Security Issue Comment")
            if security := comments.get("security"):
                log.debug("Previous version of Security Issue comment, updating")
                self.update_comment(security_comment, str(security.id))
            else:
                log.debug("No Previous version of Security Issue comment, posting")
                self.post_comment(security_comment)

    def remove_comment_alerts(self, comments: dict) -> None:
        if security_alert := comments.get("security"):
            new_body = Comments.process_security_comment(security_alert, comments)
            self.handle_ignore_reactions(comments)
            self.update_comment(new_body, str(security_alert.id))

    def handle_ignore_reactions(self, comments: dict) -> None:
        for comment in comments.get("ignore", []):
            if "SocketSecurity ignore" in comment.body and not self.comment_reaction_exists(comment.id):
                self.post_reaction(comment.id)

    def post_reaction(self, comment_id: int) -> None:
        path = f"repos/{self.config.owner}/{self.config.repository}/issues/comments/{comment_id}/reactions"
        payload = json.dumps({"content": "+1"})
        self.client.request(
            path=path,
            payload=payload,
            method="POST",
            headers=self.config.headers,
            base_url=self.config.api_url
        )

    def comment_reaction_exists(self, comment_id: int) -> bool:
        path = f"repos/{self.config.owner}/{self.config.repository}/issues/comments/{comment_id}/reactions"
        try:
            response = self.client.request(path, headers=self.config.headers, base_url=self.config.api_url)
            for reaction in response.json():
                if reaction.get("content") == ":thumbsup:":
                    return True
        except Exception as error:
            log.error(f"Unable to get reaction for {comment_id} for PR {self.config.pr_number}")
            log.error(error)
        return False
