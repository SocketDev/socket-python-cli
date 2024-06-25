import json
import os
from socketsecurity.core import log
import requests
from socketsecurity.core.exceptions import *
from socketsecurity.core.classes import GithubComment, Diff, Issue
import sys


global github_sha
global github_api_url
global github_ref_type
global github_event_name
global github_workspace
global github_repository
global github_ref_name
global github_actor
global default_branch
global github_env
global pr_number
global pr_name
global is_default_branch
global commit_message
global committer
global gh_api_token
global github_repository_owner

github_variables = [
    "GITHUB_SHA",
    "GITHUB_API_URL",
    "GITHUB_REF_TYPE",
    "GITHUB_EVENT_NAME",
    "GITHUB_WORKSPACE",
    "GITHUB_REPOSITORY",
    "GITHUB_REF_NAME",
    "DEFAULT_BRANCH",
    "PR_NUMBER",
    "PR_NAME",
    "COMMIT_MESSAGE",
    "GITHUB_ACTOR",
    "GITHUB_ENV",
    "GH_API_TOKEN",
    "GITHUB_REPOSITORY_OWNER"
]

for env in github_variables:
    var_name = env.lower()
    globals()[var_name] = os.getenv(env) or None
    if var_name == "default_branch":
        global is_default_branch
        if default_branch is None or default_branch.lower() == "false":
            is_default_branch = False
        else:
            is_default_branch = True


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
    if gh_api_token is None or gh_api_token == "":
        raise APIKeyMissing

    if headers is None:
        headers = {
            'Authorization': f"Bearer {gh_api_token}",
            'User-Agent': 'SocketPythonScript/0.0.1',
            "accept": "application/json"
        }
    url = f"{github_api_url}/{path}"
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


class Github:
    commit_sha: str
    api_url: str
    ref_type: str
    event_name: str
    workspace: str
    repository: str
    ref_name: str
    default_branch: str
    is_default_branch: bool
    pr_number: int
    pr_name: str
    commit_message: str
    committer: str
    github_env: str
    api_token: str
    project_id: int

    def __init__(self):
        self.commit_sha = github_sha
        self.api_url = github_api_url
        self.ref_type = github_ref_type
        self.event_name = github_event_name
        self.workspace = github_workspace
        self.repository = github_repository
        if "/" in self.repository:
            self.repository = self.repository.rsplit("/")[1]
        self.branch = github_ref_name
        self.default_branch = default_branch
        self.is_default_branch = is_default_branch
        self.pr_number = pr_number
        self.pr_name = pr_name
        self.commit_message = commit_message
        self.committer = github_actor
        self.github_env = github_env
        self.api_token = gh_api_token
        self.project_id = 0
        if self.api_token is None:
            print("Unable to get Github API Token from GH_API_TOKEN")
            sys.exit(2)

    @staticmethod
    def check_event_type() -> str:
        if github_event_name.lower() == "push":
            if pr_number is None or pr_number == "":
                event_type = "main"
            else:
                event_type = "diff"
        elif github_event_name.lower() == "issue_comment":
            event_type = "comment"
        else:
            event_type = None
            log.error(f"Unknown event type {github_event_name}")
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
                existing_overview_comment: GithubComment
                Github.update_comment(overview_comment, str(existing_overview_comment.id))
            else:
                Github.post_comment(overview_comment)
        if new_security_comment:
            if existing_security_comment is not None:
                existing_security_comment: GithubComment
                Github.update_comment(security_comment, str(existing_security_comment.id))
            else:
                Github.post_comment(security_comment)

    @staticmethod
    def post_comment(body: str) -> None:
        repo = github_repository.rsplit("/", 1)[1]
        path = f"repos/{github_repository_owner}/{repo}/issues/{pr_number}/comments"
        payload = {
            "body": body
        }
        payload = json.dumps(payload)
        do_request(path, payload=payload, method="POST")

    @staticmethod
    def update_comment(body: str, comment_id: str) -> None:
        repo = github_repository.rsplit("/", 1)[1]
        path = f"repos/{github_repository_owner}/{repo}/issues/comments/{comment_id}"
        payload = {
            "body": body
        }
        payload = json.dumps(payload)
        do_request(path, payload=payload, method="PATCH")

    @staticmethod
    def write_new_env(name: str, content: str) -> None:
        file = open(github_env, "a")
        new_content = content.replace("\n", "\\n")
        env_output = f"{name}={new_content}"
        file.write(env_output)

    @staticmethod
    def get_comments_for_pr(repo: str, pr: str) -> dict:
        path = f"repos/{github_repository_owner}/{repo}/issues/{pr}/comments"
        raw_comments = do_request(path)
        comments = {}
        if "error" not in raw_comments:
            for item in raw_comments:
                comment = GithubComment(**item)
                comments[comment.id] = comment
                for line in comment.body.split("\n"):
                    comment.body_list.append(line)
        else:
            log.error(raw_comments)
        socket_comments = Github.check_for_socket_comments(comments)
        return socket_comments

    @staticmethod
    def check_for_socket_comments(comments: dict):
        socket_comments = {}
        for comment_id in comments:
            comment = comments[comment_id]
            comment: GithubComment
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
        ignore_all, ignore_commands = Github.get_ignore_options(comments)
        for alert in new_alerts:
            alert: Issue
            if ignore_all:
                break
            else:
                purl = f"{alert.pkg_name}, {alert.pkg_version}"
                purl_star = f"{alert.pkg_name}, *"
                if purl in ignore_commands or purl_star in ignore_commands:
                    log.debug(f"Alerts for {alert.pkg_name}@{alert.pkg_version} ignored")
                else:
                    log.debug(f"Adding alert {alert.type} for {alert.pkg_name}@{alert.pkg_version}")
                    alerts.append(alert)
        return alerts

    @staticmethod
    def get_ignore_options(comments: dict) -> [bool, list]:
        ignore_commands = []
        ignore_all = False

        for comment in comments["ignore"]:
            comment: GithubComment
            first_line = comment.body_list[0]
            if not ignore_all and "SocketSecurity ignore" in first_line:
                first_line = first_line.lstrip("@")
                _, command = first_line.split("SocketSecurity ")
                command = command.strip()
                if command == "ignore-all":
                    ignore_all = True
                else:
                    command = command.lstrip("ignore").strip()
                    name, version = command.rsplit("@", 1)
                    ecosystem, name = name.split("/", 1)
                    data = (ecosystem, name, version)
                    ignore_commands.append(data)
        return ignore_all, ignore_commands

    @staticmethod
    def is_ignore(
            pkg_ecosystem: str,
            pkg_name: str,
            pkg_version: str,
            ecosystem: str,
            name: str,
            version: str
    ) -> bool:
        result = False
        if pkg_ecosystem == ecosystem and pkg_name == name and (pkg_version == version or version == "*"):
            result = True
        return result

    @staticmethod
    def remove_comment_alerts(comments: dict):
        security_alert = comments.get("security")
        if security_alert is not None:
            security_alert: GithubComment
            new_body = Github.process_security_comment(security_alert, comments)
            Github.update_comment(new_body, str(security_alert.id))

    @staticmethod
    def is_heading_line(line) -> bool:
        is_heading_line = True
        if line != "|Alert|Package|Introduced by|Manifest File|" and ":---" not in line:
            is_heading_line = False
        return is_heading_line

    @staticmethod
    def process_security_comment(comment: GithubComment, comments) -> str:
        lines = []
        start = False
        ignore_all, ignore_commands = Github.get_ignore_options(comments)
        for line in comment.body_list:
            line = line.strip()
            if "start-socket-alerts-table" in line:
                start = True
                lines.append(line)
            elif start and "end-socket-alerts-table" not in line and not Github.is_heading_line(line) and line != '':
                title, package, introduced_by, manifest = line.strip("|").split("|")
                details, _ = package.split("](")
                pkg_ecosystem, details = details.strip("[").split("/", 1)
                pkg_name, pkg_version = details.split("@")
                ignore = False
                for ecosystem, name, version in ignore_commands:
                    if ignore_all or Github.is_ignore(pkg_ecosystem, pkg_name, pkg_version, ecosystem, name, version):
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

