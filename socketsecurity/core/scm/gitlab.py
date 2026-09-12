import json
import os
import sys
from dataclasses import dataclass
from typing import Optional

import requests

from socketsecurity import USER_AGENT
from socketsecurity.core import log
from socketsecurity.core.classes import Comment
from socketsecurity.core.scm_comments import Comments
from socketsecurity.socketcli import CliClient


@dataclass
class GitlabConfig:
    """Configuration from GitLab environment variables"""
    commit_sha: str
    api_url: str
    project_dir: str
    mr_source_branch: Optional[str]
    mr_iid: Optional[str]
    mr_project_id: Optional[str]
    commit_message: str
    default_branch: str
    project_name: str
    pipeline_source: str
    commit_author: str
    token: str
    repository: str
    is_default_branch: bool
    headers: dict

    @classmethod
    def from_env(cls) -> 'GitlabConfig':
        token = os.getenv('GITLAB_TOKEN')
        if not token:
            log.error("Unable to get GitLab API Token from GITLAB_TOKEN")
            sys.exit(2)

        project_name = os.getenv('CI_PROJECT_NAME', '')
        if "/" in project_name:
            project_name = project_name.rsplit("/")[1]

        mr_source_branch = os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME')
        default_branch = os.getenv('CI_DEFAULT_BRANCH', '')

        # Determine which authentication pattern to use
        headers = cls._get_auth_headers(token)

        # Prefer source branch SHA (real commit) over CI_COMMIT_SHA which
        # may be a synthetic merge-result commit in merged-results pipelines.
        commit_sha = (
            os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_SHA') or
            os.getenv('CI_COMMIT_SHA', '')
        )

        return cls(
            commit_sha=commit_sha,
            api_url=os.getenv('CI_API_V4_URL', ''),
            project_dir=os.getenv('CI_PROJECT_DIR', ''),
            mr_source_branch=mr_source_branch,
            mr_iid=os.getenv('CI_MERGE_REQUEST_IID'),
            mr_project_id=os.getenv('CI_MERGE_REQUEST_PROJECT_ID'),
            commit_message=os.getenv('CI_COMMIT_MESSAGE', ''),
            default_branch=default_branch,
            project_name=project_name,
            pipeline_source=os.getenv('CI_PIPELINE_SOURCE', ''),
            commit_author=os.getenv('CI_COMMIT_AUTHOR', ''),
            token=token,
            repository=project_name,
            is_default_branch=(mr_source_branch == default_branch if mr_source_branch else False),
            headers=headers
        )

    @staticmethod
    def _get_auth_headers(token: str) -> dict:
        """
        Determine the appropriate authentication headers for GitLab API.
        
        GitLab supports two authentication patterns:
        1. Bearer token (OAuth 2.0 tokens, personal access tokens with api scope)
        2. Private token (personal access tokens)
        
        Logic for token type determination:
        - CI_JOB_TOKEN: Always use Bearer (GitLab CI job token)
        - Tokens starting with 'glpat-': Personal access tokens, try Bearer first
        - OAuth tokens: Use Bearer
        - Other tokens: Use PRIVATE-TOKEN as fallback
        """
        base_headers = {
            'User-Agent': USER_AGENT,
            "accept": "application/json"
        }
        
        # Check if this is a GitLab CI job token
        if token == os.getenv('CI_JOB_TOKEN'):
            log.debug("Using Bearer authentication for GitLab CI job token")
            return {
                **base_headers,
                'Authorization': f"Bearer {token}"
            }
        
        # Check for personal access token pattern
        if token.startswith('glpat-'):
            log.debug("Using Bearer authentication for GitLab personal access token")
            return {
                **base_headers,
                'Authorization': f"Bearer {token}"
            }
        
        # Check for OAuth token pattern (typically longer and alphanumeric)
        if len(token) > 40 and token.isalnum():
            log.debug("Using Bearer authentication for potential OAuth token")
            return {
                **base_headers,
                'Authorization': f"Bearer {token}"
            }
        
        # Default to PRIVATE-TOKEN for other token types
        log.debug("Using PRIVATE-TOKEN authentication for GitLab token")
        return {
            **base_headers,
            'PRIVATE-TOKEN': f"{token}"
        }

class Gitlab:
    # GitLab access levels: 30 Developer, 40 Maintainer, 50 Owner. Reporter (20)
    # and Guest (10) cannot push, so they cannot suppress an alert either.
    MIN_IGNORE_ACCESS_LEVEL = 30
    # Bounded so a project with a very large membership cannot stall a scan. Past
    # the cap the answer is "undetermined", handled the same as a failed lookup.
    MEMBER_PAGE_SIZE = 100
    MEMBER_PAGE_LIMIT = 10

    def __init__(
        self,
        client: CliClient,
        config: Optional[GitlabConfig] = None,
        ignore_authorization: str = "enforce",
    ):
        self.config = config or GitlabConfig.from_env()
        self.client = client
        self.ignore_authorization = ignore_authorization
        # None until the first ignore comment forces a lookup; stays None when the
        # members API cannot be read, which is the "undetermined" state.
        self._member_access: Optional[dict] = None
        self._member_lookup_attempted = False

    def _request_with_fallback(self, **kwargs):
        """
        Make a request with automatic fallback between Bearer and PRIVATE-TOKEN authentication.
        This provides robustness when the initial token type detection is incorrect.
        """
        try:
            # Try the initial request with the configured headers
            return self.client.request(**kwargs)
        except requests.exceptions.HTTPError as e:
            # Check if this is an authentication error (401)
            if e.response and e.response.status_code == 401:
                log.debug("Authentication failed with initial headers, trying fallback method")
                
                # Determine the fallback headers
                original_headers = kwargs.get('headers', self.config.headers)
                fallback_headers = self._get_fallback_headers(original_headers)
                
                if fallback_headers and fallback_headers != original_headers:
                    log.debug("Retrying request with fallback authentication method")
                    kwargs['headers'] = fallback_headers
                    return self.client.request(**kwargs)
            
            # Re-raise the original exception if it's not an auth error or fallback failed
            raise
        except Exception:
            # Handle other types of exceptions that don't have response attribute
            raise

    def _get_fallback_headers(self, original_headers: dict) -> dict:
        """
        Generate fallback authentication headers.
        If using Bearer, fallback to PRIVATE-TOKEN and vice versa.
        """
        base_headers = {
            'User-Agent': USER_AGENT,
            "accept": "application/json"
        }
        
        # If currently using Bearer, try PRIVATE-TOKEN
        if 'Authorization' in original_headers and 'Bearer' in original_headers['Authorization']:
            log.debug("Falling back from Bearer to PRIVATE-TOKEN authentication")
            return {
                **base_headers,
                'PRIVATE-TOKEN': f"{self.config.token}"
            }
        
        # If currently using PRIVATE-TOKEN, try Bearer
        elif 'PRIVATE-TOKEN' in original_headers:
            log.debug("Falling back from PRIVATE-TOKEN to Bearer authentication")
            return {
                **base_headers,
                'Authorization': f"Bearer {self.config.token}"
            }
        
        # No fallback available
        return {}

    def check_event_type(self) -> str:
        pipeline_source = self.config.pipeline_source.lower()
        if pipeline_source in ["web", 'merge_request_event', "push", "api", 'pipeline']:
            if not self.config.mr_iid:
                return "main"
            return "diff"
        elif pipeline_source == "issue_comment":
            return "comment"
        else:
            log.error(f"Unknown event type {pipeline_source}")
            sys.exit(0)

    def post_comment(self, body: str) -> None:
        path = f"projects/{self.config.mr_project_id}/merge_requests/{self.config.mr_iid}/notes"
        payload = {"body": body}
        self._request_with_fallback(
            path=path,
            payload=payload,
            method="POST",
            headers=self.config.headers,
            base_url=self.config.api_url
        )

    def update_comment(self, body: str, comment_id: str) -> None:
        path = f"projects/{self.config.mr_project_id}/merge_requests/{self.config.mr_iid}/notes/{comment_id}"
        payload = {"body": body}
        self._request_with_fallback(
            path=path,
            payload=payload,
            method="PUT",
            headers=self.config.headers,
            base_url=self.config.api_url
        )

    def has_thumbsup_reaction(self, comment_id: int) -> bool:
        """Best-effort check for 'thumbsup' award emoji on a MR note."""
        if not self.config.mr_project_id or not self.config.mr_iid:
            return False
        path = f"projects/{self.config.mr_project_id}/merge_requests/{self.config.mr_iid}/notes/{comment_id}/award_emoji"
        try:
            response = self._request_with_fallback(
                path=path,
                headers=self.config.headers,
                base_url=self.config.api_url
            )
            for emoji in response.json():
                if emoji.get("name") == "thumbsup":
                    return True
        except Exception as e:
            log.debug(f"Could not check award emoji for note {comment_id} (best effort): {e}")
        return False

    def get_comments_for_pr(self) -> dict:
        log.debug(f"Getting Gitlab comments for Repo {self.config.repository} for PR {self.config.mr_iid}")
        path = f"projects/{self.config.mr_project_id}/merge_requests/{self.config.mr_iid}/notes"
        response = self._request_with_fallback(
            path=path,
            headers=self.config.headers,
            base_url=self.config.api_url
        )
        raw_comments = Comments.process_response(response)
        comments = {}
        if "message" not in raw_comments:
            for item in raw_comments:
                comment = Comment(**item)
                comments[comment.id] = comment
                comment.body_list = comment.body.split("\n")
        else:
            log.error(raw_comments)
        gate = None if self.ignore_authorization == "off" else self.is_ignore_authorized
        return Comments.check_for_socket_comments(comments, gate)

    def _load_member_access(self) -> Optional[dict]:
        """Map project member user id -> access level, or None if unreadable.

        ``members/all`` is used rather than a per-user lookup because it answers
        non-membership with a 200 and an absent id. CliClient collapses every HTTP
        error into APIFailure without a status code, so a per-user 404 -- exactly
        the outsider case this guards against -- would be indistinguishable from a
        token that cannot read the endpoint, and would have to fail open.
        """
        if self._member_lookup_attempted:
            return self._member_access
        self._member_lookup_attempted = True
        if not self.config.mr_project_id:
            return None

        access: dict = {}
        for page in range(1, Gitlab.MEMBER_PAGE_LIMIT + 1):
            path = (
                f"projects/{self.config.mr_project_id}/members/all"
                f"?per_page={Gitlab.MEMBER_PAGE_SIZE}&page={page}"
            )
            try:
                response = self._request_with_fallback(
                    path=path,
                    headers=self.config.headers,
                    base_url=self.config.api_url
                )
                members = response.json()
            except Exception as error:
                log.warning(f"Could not read GitLab project members: {error}")
                return None
            if not isinstance(members, list):
                log.warning("Unexpected GitLab project members response")
                return None
            for member in members:
                if isinstance(member, dict) and member.get("id") is not None:
                    access[member["id"]] = member.get("access_level") or 0
            if len(members) < Gitlab.MEMBER_PAGE_SIZE:
                self._member_access = access
                return access

        log.warning(
            f"GitLab project has more than {Gitlab.MEMBER_PAGE_SIZE * Gitlab.MEMBER_PAGE_LIMIT} "
            "members; cannot confirm ignore-command authorization"
        )
        return None

    def is_ignore_authorized(self, comment: Comment) -> bool:
        """Whether a commenter may suppress alerts with @SocketSecurity ignore.

        GitLab notes carry no permission field, so this costs one members lookup
        per run (cached, and only when an ignore command is actually present).

        When membership can be read the answer is definitive. When it cannot -- a
        CI_JOB_TOKEN generally cannot read the members API -- the command is
        honored and a warning is logged, so turning this on does not silently break
        pipelines that were already relying on ignore commands. Set a token with
        API read access to get enforcement.
        """
        access = self._load_member_access()
        if access is None:
            author = Comments.comment_author_name(comment)
            if self.ignore_authorization == "strict":
                log.warning(
                    f"Rejecting @SocketSecurity ignore from {author}: GitLab project "
                    "membership could not be read and --ignore-authorization is strict."
                )
                return False
            log.warning(
                f"Honoring @SocketSecurity ignore from {author} without verifying "
                "write access: GitLab project membership could not be read. Use a "
                "token with API read access, or --ignore-authorization strict to "
                "reject instead."
            )
            return True

        author = getattr(comment, "author", None) or {}
        user_id = author.get("id")
        return access.get(user_id, 0) >= Gitlab.MIN_IGNORE_ACCESS_LEVEL

    def add_socket_comments(
            self,
            security_comment: str,
            overview_comment: str,
            comments: dict,
            new_security_comment: bool = True,
            new_overview_comment: bool = True
    ) -> None:
        existing_overview_comment = comments.get("overview")
        existing_security_comment = comments.get("security")
        if new_overview_comment:
            log.debug("New Dependency Overview comment")
            if existing_overview_comment is not None:
                log.debug("Previous version of Dependency Overview, updating")
                # Type narrowing: after None check, mypy knows this is Comment
                self.update_comment(overview_comment, str(existing_overview_comment.id))
            else:
                log.debug("No previous version of Dependency Overview, posting")
                self.post_comment(overview_comment)
        if new_security_comment:
            log.debug("New Security Issue Comment")
            if existing_security_comment is not None:
                log.debug("Previous version of Security Issue comment, updating")
                # Type narrowing: after None check, mypy knows this is Comment
                self.update_comment(security_comment, str(existing_security_comment.id))
            else:
                log.debug("No Previous version of Security Issue comment, posting")
                self.post_comment(security_comment)

    def enable_merge_pipeline_check(self) -> None:
        """Enable 'only_allow_merge_if_pipeline_succeeds' on the MR target project."""
        if not self.config.mr_project_id:
            return
        url = f"{self.config.api_url}/projects/{self.config.mr_project_id}"
        try:
            resp = requests.put(
                url,
                json={"only_allow_merge_if_pipeline_succeeds": True},
                headers=self.config.headers,
            )
            if resp.status_code == 401:
                fallback = self._get_fallback_headers(self.config.headers)
                if fallback:
                    resp = requests.put(
                        url,
                        json={"only_allow_merge_if_pipeline_succeeds": True},
                        headers=fallback,
                    )
            if resp.status_code >= 400:
                log.error(f"GitLab enable merge check API {resp.status_code}: {resp.text}")
            else:
                log.info("Enabled 'pipelines must succeed' merge check on project")
        except Exception as e:
            log.error(f"Failed to enable merge pipeline check: {e}")

    def set_commit_status(self, state: str, description: str, target_url: str = '') -> None:
        """Post a commit status to GitLab. state should be 'success' or 'failed'.

        Uses requests.post with json= directly because CliClient.request sends
        data= (form-encoded) which GitLab's commit status endpoint rejects.
        """
        if not self.config.mr_project_id:
            log.debug("No mr_project_id, skipping commit status")
            return
        url = f"{self.config.api_url}/projects/{self.config.mr_project_id}/statuses/{self.config.commit_sha}"
        payload = {
            "state": state,
            "context": "socket-security-commit-status",
            "description": description,
        }
        if self.config.mr_source_branch:
            payload["ref"] = self.config.mr_source_branch
        if target_url:
            payload["target_url"] = target_url
        try:
            log.debug(f"Posting commit status to {url}")
            resp = requests.post(url, json=payload, headers=self.config.headers)
            if resp.status_code == 401:
                fallback = self._get_fallback_headers(self.config.headers)
                if fallback:
                    resp = requests.post(url, json=payload, headers=fallback)
            if resp.status_code >= 400:
                log.error(f"GitLab commit status API {resp.status_code}: {resp.text}")
            resp.raise_for_status()
            log.info(f"Commit status set to '{state}' on {self.config.commit_sha[:8]}")
        except Exception as e:
            log.error(f"Failed to set commit status: {e}")

    def post_thumbsup_reaction(self, comment_id: int) -> None:
        """Best-effort: add 'thumbsup' award emoji to a MR note."""
        if not self.config.mr_project_id or not self.config.mr_iid:
            return
        path = f"projects/{self.config.mr_project_id}/merge_requests/{self.config.mr_iid}/notes/{comment_id}/award_emoji"
        try:
            headers = {**self.config.headers, "Content-Type": "application/json"}
            self._request_with_fallback(
                path=path,
                payload=json.dumps({"name": "thumbsup"}),
                method="POST",
                headers=headers,
                base_url=self.config.api_url
            )
        except Exception as e:
            log.debug(f"Could not add thumbsup emoji to note {comment_id} (best effort): {e}")

    def handle_ignore_reactions(self, comments: dict) -> None:
        for comment in comments.get("ignore", []):
            if "SocketSecurity ignore" in comment.body and not self.has_thumbsup_reaction(comment.id):
                self.post_thumbsup_reaction(comment.id)

    def remove_comment_alerts(self, comments: dict):
        security_alert = comments.get("security")
        if security_alert is not None:
            # Type narrowing: after None check, mypy knows this is Comment
            new_body = Comments.process_security_comment(security_alert, comments)
            self.handle_ignore_reactions(comments)
            self.update_comment(new_body, str(security_alert.id))
