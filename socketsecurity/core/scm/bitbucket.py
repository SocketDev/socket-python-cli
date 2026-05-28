import base64
import json
import os
import sys
from dataclasses import dataclass
from typing import Optional

from socketsecurity import USER_AGENT
from socketsecurity.core import log
from socketsecurity.core.classes import Comment
from socketsecurity.core.scm_comments import Comments
from socketsecurity.socketcli import CliClient


@dataclass
class BitbucketConfig:
    """Configuration from Bitbucket Pipelines environment variables."""
    api_url: str
    workspace: str
    repo_slug: str
    repository: str
    pr_id: Optional[str]
    source_branch: Optional[str]
    destination_branch: Optional[str]
    default_branch: Optional[str]
    commit_sha: str
    is_default_branch: bool
    token: str
    username: Optional[str]
    headers: dict

    @classmethod
    def from_env(cls, pr_number: Optional[str] = None) -> "BitbucketConfig":
        """Create config from Bitbucket Pipelines env vars.

        Supports two auth styles:
        - Bearer: BITBUCKET_TOKEN (workspace/repo/project access tokens, OAuth)
        - Basic: BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD
        """
        token = os.getenv("BITBUCKET_TOKEN", "")
        username = os.getenv("BITBUCKET_USERNAME")
        app_password = os.getenv("BITBUCKET_APP_PASSWORD")

        if not token and not (username and app_password):
            log.error(
                "Unable to get Bitbucket credentials. Set BITBUCKET_TOKEN, "
                "or BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD."
            )
            sys.exit(2)

        api_url = os.getenv("BITBUCKET_API_URL", "https://api.bitbucket.org/2.0").rstrip("/")

        repo_full_name = os.getenv("BITBUCKET_REPO_FULL_NAME", "")
        workspace = os.getenv("BITBUCKET_WORKSPACE", "")
        repo_slug = os.getenv("BITBUCKET_REPO_SLUG", "")
        if repo_full_name and "/" in repo_full_name:
            full_workspace, full_slug = repo_full_name.split("/", 1)
            workspace = workspace or full_workspace
            repo_slug = repo_slug or full_slug

        pr_id = pr_number or os.getenv("BITBUCKET_PR_ID")
        if pr_id == "0":
            pr_id = None

        source_branch = os.getenv("BITBUCKET_BRANCH")
        destination_branch = os.getenv("BITBUCKET_PR_DESTINATION_BRANCH")
        default_branch = os.getenv("BITBUCKET_DEFAULT_BRANCH")
        commit_sha = os.getenv("BITBUCKET_COMMIT", "")

        is_default_branch = bool(
            source_branch and default_branch and source_branch == default_branch
        )

        headers = cls._get_auth_headers(token, username, app_password)

        return cls(
            api_url=api_url,
            workspace=workspace,
            repo_slug=repo_slug,
            repository=repo_slug,
            pr_id=pr_id,
            source_branch=source_branch,
            destination_branch=destination_branch,
            default_branch=default_branch,
            commit_sha=commit_sha,
            is_default_branch=is_default_branch,
            token=token,
            username=username,
            headers=headers,
        )

    @staticmethod
    def _get_auth_headers(
        token: str,
        username: Optional[str],
        app_password: Optional[str],
    ) -> dict:
        base_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if token:
            return {**base_headers, "Authorization": f"Bearer {token}"}
        encoded = base64.b64encode(f"{username}:{app_password}".encode()).decode("ascii")
        return {**base_headers, "Authorization": f"Basic {encoded}"}


class Bitbucket:
    def __init__(self, client: CliClient, config: Optional[BitbucketConfig] = None):
        self.config = config or BitbucketConfig.from_env()
        self.client = client

    def check_event_type(self) -> str:
        """Bitbucket Pipelines does not expose a 'comment' trigger.

        If a PR id is set we treat the run as a diff; otherwise main branch.
        """
        if self.config.pr_id:
            return "diff"
        return "main"

    def _pr_comments_path(self, comment_id: Optional[str] = None) -> str:
        base = (
            f"repositories/{self.config.workspace}/{self.config.repo_slug}"
            f"/pullrequests/{self.config.pr_id}/comments"
        )
        if comment_id:
            return f"{base}/{comment_id}"
        return base

    def post_comment(self, body: str) -> None:
        path = self._pr_comments_path()
        payload = json.dumps({"content": {"raw": body}})
        self.client.request(
            path=path,
            payload=payload,
            method="POST",
            headers=self.config.headers,
            base_url=self.config.api_url,
        )

    def update_comment(self, body: str, comment_id: str) -> None:
        path = self._pr_comments_path(comment_id)
        payload = json.dumps({"content": {"raw": body}})
        self.client.request(
            path=path,
            payload=payload,
            method="PUT",
            headers=self.config.headers,
            base_url=self.config.api_url,
        )

    def get_comments_for_pr(self) -> dict:
        log.debug(
            f"Getting Bitbucket comments for Repo {self.config.repo_slug} "
            f"for PR {self.config.pr_id}"
        )
        comments: dict = {}
        if not self.config.pr_id:
            return comments

        next_url: Optional[str] = None
        first_path = f"{self._pr_comments_path()}?pagelen=100"

        while True:
            if next_url:
                # Bitbucket returns absolute 'next' URLs; pass via base_url=''.
                response = self.client.request(
                    path=next_url,
                    headers=self.config.headers,
                    base_url="",
                )
            else:
                response = self.client.request(
                    path=first_path,
                    headers=self.config.headers,
                    base_url=self.config.api_url,
                )
            data = Comments.process_response(response)
            if not isinstance(data, dict):
                log.error(f"Unexpected Bitbucket comments response: {data}")
                break
            if data.get("type") == "error" or "error" in data:
                log.error(data)
                break

            for raw in data.get("values", []):
                normalized = self._normalize_comment(raw)
                if normalized is None:
                    continue
                comment = Comment(**normalized)
                comment.body_list = comment.body.split("\n")
                comments[comment.id] = comment

            next_url = data.get("next")
            if not next_url:
                break

        return Comments.check_for_socket_comments(comments)

    @staticmethod
    def _normalize_comment(raw: dict) -> Optional[dict]:
        """Map a Bitbucket Cloud comment payload to the Comment shape."""
        if not isinstance(raw, dict):
            return None
        if raw.get("deleted"):
            return None
        content = raw.get("content") or {}
        body = content.get("raw") or content.get("markup") or ""
        user = raw.get("user") or {}
        normalized_user = {
            "login": user.get("nickname") or user.get("display_name", ""),
            "username": user.get("nickname") or user.get("display_name", ""),
            "id": user.get("uuid", ""),
            "display_name": user.get("display_name", ""),
        }
        return {
            "id": raw.get("id"),
            "body": body,
            "user": normalized_user,
            "created_at": raw.get("created_on", ""),
            "updated_at": raw.get("updated_on", ""),
            "html_url": (raw.get("links") or {}).get("html", {}).get("href", ""),
            "url": (raw.get("links") or {}).get("self", {}).get("href", ""),
            "reactions": {},
        }

    def add_socket_comments(
        self,
        security_comment: str,
        overview_comment: str,
        comments: dict,
        new_security_comment: bool = True,
        new_overview_comment: bool = True,
    ) -> None:
        if not self.config.pr_id:
            log.debug("No Bitbucket PR id, skipping comment posting")
            return

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
                log.debug("No previous version of Security Issue comment, posting")
                self.post_comment(security_comment)

    def handle_ignore_reactions(self, comments: dict) -> None:
        """Bitbucket Cloud comments have no native reactions API equivalent.

        We mark ignore comments as processed by editing them to append a
        hidden Socket marker. Subsequent runs check for this marker via
        has_thumbsup_reaction().
        """
        for comment in comments.get("ignore", []):
            if "SocketSecurity ignore" in comment.body and not self.has_thumbsup_reaction(comment.id):
                self._mark_comment_processed(comment)

    PROCESSED_MARKER = "<!-- socket-ignore-processed -->"

    def has_thumbsup_reaction(self, comment_id) -> bool:
        """Bitbucket has no reactions; detect our hidden processed marker."""
        if not self.config.pr_id:
            return False
        try:
            response = self.client.request(
                path=self._pr_comments_path(str(comment_id)),
                headers=self.config.headers,
                base_url=self.config.api_url,
            )
            data = response.json() if hasattr(response, "json") else {}
            body = ((data or {}).get("content") or {}).get("raw", "")
            return self.PROCESSED_MARKER in body
        except Exception as error:
            log.debug(f"Could not fetch Bitbucket comment {comment_id} for marker check: {error}")
            return False

    def _mark_comment_processed(self, comment) -> None:
        if self.PROCESSED_MARKER in comment.body:
            return
        new_body = f"{comment.body}\n\n{self.PROCESSED_MARKER}"
        try:
            self.update_comment(new_body, str(comment.id))
        except Exception as error:
            log.debug(f"Failed to mark Bitbucket ignore comment {comment.id} as processed: {error}")

    def remove_comment_alerts(self, comments: dict) -> None:
        if security_alert := comments.get("security"):
            new_body = Comments.process_security_comment(security_alert, comments)
            self.handle_ignore_reactions(comments)
            self.update_comment(new_body, str(security_alert.id))
