import json
import os
from socketsecurity.core import log
import requests
from socketsecurity.core.exceptions import *
from socketsecurity.core.classes import GitlabComment, Diff, Issue
import sys


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
                existing_overview_comment: GitlabComment
                Gitlab.update_comment(overview_comment, str(existing_overview_comment.id))
            else:
                Gitlab.post_comment(overview_comment)
        if new_security_comment:
            if existing_security_comment is not None:
                existing_security_comment: GitlabComment
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
                comment = GitlabComment(**item)
                comments[comment.id] = comment
                for line in comment.body.split("\n"):
                    comment.body_list.append(line)
        else:
            log.error(raw_comments)
        socket_comments = Gitlab.check_for_socket_comments(comments)
        return socket_comments

    @staticmethod
    def check_for_socket_comments(comments: dict):
        socket_comments = {}
        for comment_id in comments:
            comment = comments[comment_id]
            comment: GitlabComment
            if "socket-security-comment-actions" in comment.body:
                socket_comments["security"] = comment
            elif "socket-overview-comment-actions" in comment.body:
                socket_comments["overview"] = comment
            elif "SocketSecurity ignore" in comment.body:
                if "ignore" not in socket_comments:
                    socket_comments["ignore"] = []
                socket_comments["ignore"].append(comment)
        return socket_comments

    @staticmethod
    def remove_alerts(comments: dict, new_alerts: list) -> list:
        alerts = []
        if "ignore" not in comments:
            return new_alerts
        ignore_all, ignore_commands = Gitlab.get_ignore_options(comments)
        for alert in new_alerts:
            alert: Issue
            if ignore_all:
                break
            else:
                purl = f"{alert.pkg_name}, {alert.pkg_version}"
                purl_star = f"{alert.pkg_name}, *"
                if purl in ignore_commands or purl_star in ignore_commands:
                    print(f"Alerts for {alert.pkg_name}@{alert.pkg_version} ignored")
                else:
                    print(f"Adding alert {alert.type} for {alert.pkg_name}@{alert.pkg_version}")
                    alerts.append(alert)
        return alerts

    @staticmethod
    def get_ignore_options(comments: dict) -> [bool, list]:
        ignore_commands = []
        ignore_all = False

        for comment in comments["ignore"]:
            comment: GitlabComment
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
            security_alert: GitlabComment
            new_body = Gitlab.process_security_comment(security_alert, comments)
            Gitlab.update_comment(new_body, str(security_alert.id))

    @staticmethod
    def is_heading_line(line) -> bool:
        is_heading_line = True
        if line != "|Alert|Package|Introduced by|Manifest File|" and ":---" not in line:
            is_heading_line = False
        return is_heading_line

    @staticmethod
    def process_security_comment(comment: GitlabComment, comments) -> str:
        lines = []
        start = False
        ignore_all, ignore_commands = Gitlab.get_ignore_options(comments)
        for line in comment.body_list:
            line = line.strip()
            if "start-socket-alerts-table" in line:
                start = True
                lines.append(line)
            elif start and "end-socket-alerts-table" not in line and not Gitlab.is_heading_line(line) and line != '':
                title, package, introduced_by, manifest = line.lstrip("|").rstrip("|").split("|")
                details, _ = package.split("](")
                ecosystem, details = details.split("/", 1)
                pkg_name, pkg_version = details.split("@")
                ignore = False
                for name, version in ignore_commands:
                    if ignore_all or Gitlab.is_ignore(pkg_name, pkg_version, name, version):
                        ignore = True
                if not ignore:
                    lines.append(line)
            elif "end-socket-alerts-table" in line:
                start = False
                lines.append(line)
            else:
                lines.append(line)
        new_body = "\n".join(lines)
        return new_body

