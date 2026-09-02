import re
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import urlparse

from socketsecurity.core.git_remote import parse_git_remote


@dataclass(frozen=True)
class PullRequestContext:
    number: int = 0
    url: Optional[str] = None


def _positive_int(value) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0


def _repository_url(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    url = value.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    parsed = urlparse(url)
    return url if parsed.scheme in ("http", "https") and parsed.netloc else None


def _github_number(env: Mapping[str, str]) -> int:
    number = _positive_int(env.get("PR_NUMBER"))
    if number:
        return number
    match = re.match(r"^refs/pull/(\d+)/", env.get("GITHUB_REF", ""))
    return _positive_int(match.group(1)) if match else 0


def _github_url(number: int, repo: Optional[str], env: Mapping[str, str]) -> Optional[str]:
    remote_host, remote_path = parse_git_remote(env.get("BUILDKITE_REPO"))
    # config.repo is only ever a bare repository name, so it cannot produce a
    # slug on its own; it is kept last for callers that pass a full owner/repo.
    repository = env.get("GITHUB_REPOSITORY") or remote_path or repo
    if not repository or "/" not in repository:
        return None
    server = env.get("GITHUB_SERVER_URL") or (f"https://{remote_host}" if remote_host else "")
    server = (server or "https://github.com").rstrip("/")
    return f"{server}/{repository.strip('/')}/pull/{number}"


def _gitlab_url(number: int, repo: Optional[str], env: Mapping[str, str]) -> Optional[str]:
    project_url = _repository_url(env.get("CI_PROJECT_URL"))
    if not project_url:
        remote_host, remote_path = parse_git_remote(env.get("BUILDKITE_REPO"))
        project_path = env.get("CI_PROJECT_PATH") or remote_path or repo
        server = env.get("CI_SERVER_URL") or (f"https://{remote_host}" if remote_host else "")
        server = server.rstrip("/")
        if server and project_path and "/" in project_path:
            project_url = f"{server}/{project_path.strip('/')}"
    return f"{project_url}/-/merge_requests/{number}" if project_url else None


def _azure_url(number: int, env: Mapping[str, str], github_pr: bool) -> Optional[str]:
    repository_url = _repository_url(
        env.get("BUILD_REPOSITORY_URI") or
        env.get("SYSTEM_PULLREQUEST_SOURCEREPOSITORYURI")
    )
    if not repository_url:
        return None
    github_pr = github_pr or "github" in urlparse(repository_url).netloc.lower()
    path = "pull" if github_pr else "pullrequest"
    return f"{repository_url}/{path}/{number}"


def resolve_pull_request_context(
    integration_type: str,
    configured_number,
    repo: Optional[str],
    *,
    configured_explicit: bool = False,
    env: Optional[Mapping[str, str]] = None,
) -> PullRequestContext:
    """Resolve PR metadata without making provider API calls.

    Explicit CLI/config values win, including an explicit zero used to disable
    association. Otherwise the provider's standard CI environment is used.
    """
    environment = env or {}
    provider = str(integration_type or "api").lower()
    number = _positive_int(configured_number)

    if not configured_explicit and not number:
        if provider == "github":
            number = _github_number(environment)
        elif provider == "gitlab":
            number = _positive_int(environment.get("CI_MERGE_REQUEST_IID"))
        elif provider == "azure":
            number = (
                _positive_int(environment.get("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER")) or
                _positive_int(environment.get("SYSTEM_PULLREQUEST_PULLREQUESTID"))
            )

    if not number:
        return PullRequestContext()

    if provider == "github":
        url = _github_url(number, repo, environment)
    elif provider == "gitlab":
        url = _gitlab_url(number, repo, environment)
    elif provider == "azure":
        github_pr = bool(environment.get("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER"))
        url = _azure_url(number, environment, github_pr)
    else:
        url = None

    return PullRequestContext(number=number, url=url)
