import os
from socketsecurity.core import log
import requests
from socketsecurity.core.exceptions import *
from socketsecurity.core.scm_comments import Comments
import sys
from socketsecurity.core.classes import Comment, Issue

global ci_commit_sha
global ci_api_v4_url
global ci_project_dir
global ci_merge_request_source_branch_name
global ci_merge_request_iid
global ci_merge_request_project_id
global ci_commit_message
global ci_default_branch
global ci_project_name
global ci_pipeline_source
global ci_commit_author
global project_dir
global pr_name
global is_default_branch
global committer
global gitlab_token

gitlab_variables = [
    "CI_COMMIT_SHA",
    "CI_API_V4_URL",
    "CI_PROJECT_DIR",
    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
    "CI_MERGE_REQUEST_IID",
    "CI_MERGE_REQUEST_PROJECT_ID",
    "CI_COMMIT_MESSAGE",
    "CI_DEFAULT_BRANCH",
    "CI_PROJECT_NAME",
    "CI_PIPELINE_SOURCE",
    "CI_COMMIT_AUTHOR",
    "PROJECT_DIR",
    "DEFAULT_BRANCH",
    "PR_NAME",
    "GITLAB_TOKEN",
]


for env in gitlab_variables:
    var_name = env.lower()
    globals()[var_name] = os.getenv(env) or None


def do_request(
        path: str,
        headers: dict = None,
        payload: [dict, str] = None,
        files: list = None,
        method: str = "GET",
) -> dict:
    """
    do_requests is the shared function for making HTTP calls

    :param path: Required path for the request
    :param headers: Optional dictionary of headers. If not set will use a default set
    :param payload: Optional dictionary or string of the payload to pass
    :param files: Optional list of files to upload
    :param method: Optional method to use, defaults to GET
    :return:
    """
    if gitlab_token is None or gitlab_token == "":
        raise APIKeyMissing

    if headers is None:
        headers = {
            'Authorization': f"Bearer {gitlab_token}",
            'User-Agent': 'SocketPythonScript/0.0.1',
            "accept": "application/json"
        }
    url = f"{ci_api_v4_url}/{path}"
    response = requests.request(
        method.upper(),
        url,
        headers=headers,
        data=payload,
        files=files
    )
    if response.status_code <= 399:
        try:
            return response.json()
        except Exception as error:
            response = {
                "error": error,
                "response": response.text
            }
            return response
    else:
        msg = {
            "status_code": response.status_code,
            "UnexpectedError": "There was an unexpected error using the API",
            "error": response.text
        }
        raise APIFailure(msg)


class Gitlab:
    commit_sha: str
    api_url: str
    ref_type: str
    event_name: str
    workspace: str
    repository: str
    branch: str
    default_branch: str
    is_default_branch: bool
    pr_number: int
    pr_name: str
    commit_message: str
    committer: str
    api_token: str
    project_id: int

    def __init__(self):
        self.commit_sha = ci_commit_sha
        self.api_url = ci_api_v4_url
        self.ref_type = ""
        self.event_name = ci_pipeline_source
        self.workspace = ci_project_dir
        self.repository = ci_project_name
        if "/" in self.repository:
            self.repository = self.repository.rsplit("/")[1]
        self.branch = ci_merge_request_source_branch_name
        self.default_branch = ci_default_branch
        if self.branch == self.default_branch:
            self.is_default_branch = True
        else:
            self.is_default_branch = False
        self.pr_number = ci_merge_request_iid
        self.pr_name = pr_name
        self.commit_message = ci_commit_message
        self.committer = ci_commit_author
        self.api_token = gitlab_token
        self.project_id = ci_merge_request_project_id
        if self.api_token is None:
            print("Unable to get gitlab API Token from GITLAB_TOKEN")
            sys.exit(2)

    @staticmethod
    def check_event_type() -> str:
        if ci_pipeline_source.lower() == "push" or ci_pipeline_source.lower() == 'merge_request_event':
            if ci_merge_request_iid is None or ci_merge_request_iid == "" or str(ci_merge_request_iid) == "0":
                event_type = "main"
            else:
                event_type = "diff"
        elif ci_pipeline_source.lower() == "issue_comment":
            event_type = "comment"
        else:
            log.error(f"Unknown event type {ci_pipeline_source}")
            sys.exit(1)
        return event_type

    @staticmethod
    def add_socket_comments(
            security_comment: str,
            overview_comment: str,
            comments: dict,
            new_security_comment: bool = True,
            new_overview_comment: bool = True
    ) -> None:
        existing_overview_comment = comments.get("overview")
        existing_security_comment = comments.get("security")
        if new_overview_comment:
            if existing_overview_comment is not None:
                existing_overview_comment: Comment
                Gitlab.update_comment(overview_comment, str(existing_overview_comment.id))
            else:
                Gitlab.post_comment(overview_comment)
        if new_security_comment:
            if existing_security_comment is not None:
                existing_security_comment: Comment
                Gitlab.update_comment(security_comment, str(existing_security_comment.id))
            else:
                Gitlab.post_comment(security_comment)

    @staticmethod
    def post_comment(body: str) -> None:
        path = f"projects/{ci_merge_request_project_id}/merge_requests/{ci_merge_request_iid}/notes"
        payload = {
            "body": body
        }
        # payload = json.dumps(payload)
        do_request(path, payload=payload, method="POST")

    @staticmethod
    def update_comment(body: str, comment_id: str) -> None:
        path = f"projects/{ci_merge_request_project_id}/merge_requests/{ci_merge_request_iid}/notes/{comment_id}"
        payload = {
            "body": body
        }
        # payload = json.dumps(payload)
        do_request(path, payload=payload, method="PUT")

    @staticmethod
    def get_comments_for_pr(repo: str, pr: str) -> dict:
        path = f"projects/{ci_merge_request_project_id}/merge_requests/{ci_merge_request_iid}/notes"
        raw_comments = do_request(path)
        comments = {}
        if "message" not in raw_comments:
            for item in raw_comments:
                comment = Comment(**item)
                comments[comment.id] = comment
                for line in comment.body.split("\n"):
                    comment.body_list.append(line)
        else:
            log.error(raw_comments)
        socket_comments = Comments.check_for_socket_comments(comments)
        return socket_comments

    @staticmethod
    def get_ignore_options(comments: dict) -> [bool, list]:
        ignore_commands = []
        ignore_all = False

        for comment in comments["ignore"]:
            comment: Comment
            first_line = comment.body_list[0]
            if not ignore_all and "SocketSecurity ignore" in first_line:
                first_line = first_line.lstrip("@")
                _, command = first_line.split("SocketSecurity ")
                command = command.strip()
                if command == "ignore-all":
                    ignore_all = True
                else:
                    command = command.lstrip("ignore").strip()
                    name, version = command.split("@")
                    data = f"{name}, {version}"
                    ignore_commands.append(data)
        return ignore_all, ignore_commands

    @staticmethod
    def is_ignore(pkg_name: str, pkg_version: str, name: str, version: str) -> bool:
        result = False
        if pkg_name == name and (pkg_version == version or version == "*"):
            result = True
        return result

    @staticmethod
    def remove_comment_alerts(comments: dict):
        security_alert = comments.get("security")
        if security_alert is not None:
            security_alert: Comment
            new_body = Comments.process_security_comment(security_alert, comments)
            Gitlab.update_comment(new_body, str(security_alert.id))
