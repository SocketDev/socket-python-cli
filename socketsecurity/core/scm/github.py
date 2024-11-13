import json
import os
import sys
from dataclasses import dataclass

from git import Optional

from socketsecurity.core import do_request, log
from socketsecurity.core.classes import Comment
from socketsecurity.core.scm_comments import Comments

# Declare all globals with initial None values
github_sha: Optional[str] = None
github_api_url: Optional[str] = None
github_ref_type: Optional[str] = None
github_event_name: Optional[str] = None
github_workspace: Optional[str] = None
github_repository: Optional[str] = None
github_ref_name: Optional[str] = None
github_actor: Optional[str] = None
default_branch: Optional[str] = None
github_env: Optional[str] = None
pr_number: Optional[str] = None
pr_name: Optional[str] = None
is_default_branch: bool = False
commit_message: Optional[str] = None
committer: Optional[str] = None
gh_api_token: Optional[str] = None
github_repository_owner: Optional[str] = None
event_action: Optional[str] = None

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
    pr_number: Optional[str]
    pr_name: Optional[str]
    commit_message: Optional[str]
    actor: str
    env: str
    token: str
    owner: str
    event_action: Optional[str]

    @classmethod
    def from_env(cls) -> 'GithubConfig':
        """Create config from environment variables"""
        token = os.getenv('GH_API_TOKEN')
        if not token:
            log.error("Unable to get Github API Token from GH_API_TOKEN")
            sys.exit(2)

        return cls(
            sha=os.getenv('GITHUB_SHA', ''),
            api_url=os.getenv('GITHUB_API_URL', ''),
            ref_type=os.getenv('GITHUB_REF_TYPE', ''),
            event_name=os.getenv('GITHUB_EVENT_NAME', ''),
            workspace=os.getenv('GITHUB_WORKSPACE', ''),
            repository=os.getenv('GITHUB_REPOSITORY', '').split('/')[-1],
            ref_name=os.getenv('GITHUB_REF_NAME', ''),
            default_branch=os.getenv('DEFAULT_BRANCH', '').lower() == 'true',
            pr_number=os.getenv('PR_NUMBER'),
            pr_name=os.getenv('PR_NAME'),
            commit_message=os.getenv('COMMIT_MESSAGE'),
            actor=os.getenv('GITHUB_ACTOR', ''),
            env=os.getenv('GITHUB_ENV', ''),
            token=token,
            owner=os.getenv('GITHUB_REPOSITORY_OWNER', ''),
            event_action=os.getenv('EVENT_ACTION')
        )


for env in github_variables:
    var_name = env.lower()
    globals()[var_name] = os.getenv(env) or None
    if var_name == "default_branch":
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
        try:
            response = do_request(path, headers=headers, base_url=github_api_url)
            data = response.json()
            for reaction in data:
                content = reaction.get("content")
                if content is not None and content == ":thumbsup:":
                    return True
        except Exception as error:
            log.error(f"Unable to get reaction for {comment_id} for PR {pr_number}")
            log.error(error)
        return False
