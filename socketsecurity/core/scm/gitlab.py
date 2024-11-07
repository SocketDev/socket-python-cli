import os
import sys
from dataclasses import dataclass
from typing import Optional

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

        return cls(
            commit_sha=os.getenv('CI_COMMIT_SHA', ''),
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
            headers={
                'Authorization': f"Bearer {token}",
                'User-Agent': 'SocketPythonScript/0.0.1',
                "accept": "application/json"
            }
        )

class Gitlab:
    def __init__(self, client: CliClient, config: Optional[GitlabConfig] = None):
        self.config = config or GitlabConfig.from_env()
        self.client = client

    def check_event_type(self) -> str:
        pipeline_source = self.config.pipeline_source.lower()
        if pipeline_source in ["web", 'merge_request_event', "push"]:
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
        self.client.request(
            path=path,
            payload=payload,
            method="POST",
            headers=self.config.headers,
            base_url=self.config.api_url
        )

    def update_comment(self, body: str, comment_id: str) -> None:
        path = f"projects/{self.config.mr_project_id}/merge_requests/{self.config.mr_iid}/notes/{comment_id}"
        payload = {"body": body}
        self.client.request(
            path=path,
            payload=payload,
            method="PUT",
            headers=self.config.headers,
            base_url=self.config.api_url
        )

    def get_comments_for_pr(self) -> dict:
        log.debug(f"Getting Gitlab comments for Repo {self.config.repository} for PR {self.config.mr_iid}")
        path = f"projects/{self.config.mr_project_id}/merge_requests/{self.config.mr_iid}/notes"
        response = self.client.request(
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
        return Comments.check_for_socket_comments(comments)

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
                existing_overview_comment: Comment
                self.update_comment(overview_comment, str(existing_overview_comment.id))
            else:
                log.debug("No previous version of Dependency Overview, posting")
                self.post_comment(overview_comment)
        if new_security_comment:
            log.debug("New Security Issue Comment")
            if existing_security_comment is not None:
                log.debug("Previous version of Security Issue comment, updating")
                existing_security_comment: Comment
                self.update_comment(security_comment, str(existing_security_comment.id))
            else:
                log.debug("No Previous version of Security Issue comment, posting")
                self.post_comment(security_comment)

    def remove_comment_alerts(self, comments: dict):
        security_alert = comments.get("security")
        if security_alert is not None:
            security_alert: Comment
            new_body = Comments.process_security_comment(security_alert, comments)
            self.update_comment(new_body, str(security_alert.id))
