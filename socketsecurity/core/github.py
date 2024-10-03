import json
import os
from socketsecurity.core import log, do_request
import requests
from socketsecurity.core.classes import Comment
from socketsecurity.core.scm_comments import Comments
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
global event_action

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
    "GITHUB_REPOSITORY_OWNER",
    "EVENT_ACTION"
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
        if var_name != "gh_api_token":
            value = globals()[var_name] = os.getenv(env) or None
            log.debug(f"{env}={value}")

headers = {
    'Authorization': f"Bearer {gh_api_token}",
    'User-Agent': 'SocketPythonScript/0.0.1',
    "accept": "application/json"
}


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
    event_action: str

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
        self.event_action = event_action
        if self.api_token is None:
            print("Unable to get Github API Token from GH_API_TOKEN")
            sys.exit(2)

    @staticmethod
    def check_event_type() -> str:
        if github_event_name.lower() == "push":
            if pr_number is None or pr_number == "" or pr_number == "0":
                event_type = "main"
            else:
                event_type = "diff"
        elif github_event_name.lower() == "pull_request":
            if event_action is not None and event_action != "" and (
                    event_action.lower() == "opened" or event_action.lower() == 'synchronize'):
                event_type = "diff"
            else:
                log.info(f"Pull Request Action {event_action} is not a supported type")
                sys.exit(0)
        elif github_event_name.lower() == "issue_comment":
            event_type = "comment"
        else:
            event_type = None
            log.error(f"Unknown event type {github_event_name}")
            sys.exit(0)
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
            log.debug("New Dependency Overview comment")
            if existing_overview_comment is not None:
                log.debug("Previous version of Dependency Overview, updating")
                existing_overview_comment: Comment
                Github.update_comment(overview_comment, str(existing_overview_comment.id))
            else:
                log.debug("No previous version of Dependency Overview, posting")
                Github.post_comment(overview_comment)
        if new_security_comment:
            log.debug("New Security Issue Comment")
            if existing_security_comment is not None:
                log.debug("Previous version of Security Issue comment, updating")
                existing_security_comment: Comment
                Github.update_comment(security_comment, str(existing_security_comment.id))
            else:
                log.debug("No Previous version of Security Issue comment, posting")
                Github.post_comment(security_comment)

    @staticmethod
    def post_comment(body: str) -> None:
        repo = github_repository.rsplit("/", 1)[1]
        path = f"repos/{github_repository_owner}/{repo}/issues/{pr_number}/comments"
        payload = {
            "body": body
        }
        payload = json.dumps(payload)
        do_request(path, payload=payload, method="POST", headers=headers, base_url=github_api_url)

    @staticmethod
    def update_comment(body: str, comment_id: str) -> None:
        repo = github_repository.rsplit("/", 1)[1]
        path = f"repos/{github_repository_owner}/{repo}/issues/comments/{comment_id}"
        payload = {
            "body": body
        }
        payload = json.dumps(payload)
        do_request(path, payload=payload, method="PATCH", headers=headers, base_url=github_api_url)

    @staticmethod
    def write_new_env(name: str, content: str) -> None:
        file = open(github_env, "a")
        new_content = content.replace("\n", "\\n")
        env_output = f"{name}={new_content}"
        file.write(env_output)

    @staticmethod
    def get_comments_for_pr(repo: str, pr: str) -> dict:
        path = f"repos/{github_repository_owner}/{repo}/issues/{pr}/comments"
        raw_comments = Comments.process_response(do_request(path, headers=headers, base_url=github_api_url))
        comments = {}
        if "error" not in raw_comments:
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
    def remove_comment_alerts(comments: dict):
        security_alert = comments.get("security")
        if security_alert is not None:
            security_alert: Comment
            new_body = Comments.process_security_comment(security_alert, comments)
            Github.handle_ignore_reactions(comments)
            Github.update_comment(new_body, str(security_alert.id))

    @staticmethod
    def handle_ignore_reactions(comments: dict) -> None:
        for comment in comments["ignore"]:
            comment: Comment
            if "SocketSecurity ignore" in comment.body:
                if not Github.comment_reaction_exists(comment.id):
                    Github.post_reaction(comment.id)

    @staticmethod
    def post_reaction(comment_id: int) -> None:
        repo = github_repository.rsplit("/", 1)[1]
        path = f"repos/{github_repository_owner}/{repo}/issues/comments/{comment_id}/reactions"
        payload = {
            "content": "+1"
        }
        payload = json.dumps(payload)
        do_request(path, payload=payload, method="POST", headers=headers, base_url=github_api_url)

    @staticmethod
    def comment_reaction_exists(comment_id: int) -> bool:
        repo = github_repository.rsplit("/", 1)[1]
        path = f"repos/{github_repository_owner}/{repo}/issues/comments/{comment_id}/reactions"
        response = do_request(path, headers=headers, base_url=github_api_url)
        exists = False
        try:
            data = response.json()
            for reaction in data:
                content = reaction.get("content")
                if content is not None and content == ":thumbsup:":
                    exists = True
        except Exception as error:
            log.error(f"Unable to get reaction for {comment_id} for PR {pr_number}")
            log.error(error)
        return  exists
