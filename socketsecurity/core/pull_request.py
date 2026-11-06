import re
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import urlparse

from socketsecurity.core.git_remote import parse_git_remote


@dataclass(frozen=True)
class PullRequestContext:
    number: int = 0
    url: Optional[str] = None


def parse_pull_request_number(value) -> int:
    """Coerce a configured or CI-supplied pull request number to a positive int.

    Anything that is not a positive integer means "no pull request", including the
    literal ``false`` that Buildkite puts in ``BUILDKITE_PULL_REQUEST`` on non-PR
    builds. Callers that hand the value on to a comment adapter should store this
    result rather than the raw string, which is truthy.
    """
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0


def _http_url(value: Optional[str]) -> Optional[str]:
    """Return ``value`` if it is an http(s) URL with a host, else ``None``.

    Every URL fragment read out of the CI environment goes through here before it
    is composed into a link, because the result is sent to the API as a diff scan's
    ``external_href``. Standard runners set these variables themselves, so this is
    defense in depth rather than a live hole.
    """
    if not value:
        return None
    url = value.strip().rstrip("/")
    parsed = urlparse(url)
    return url if parsed.scheme in ("http", "https") and parsed.netloc else None


def _repository_url(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    url = value.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    return _http_url(url)


def _github_number(env: Mapping[str, str]) -> int:
    number = parse_pull_request_number(env.get("PR_NUMBER"))
    if number:
        return number
    match = re.match(r"^refs/pull/(\d+)/", env.get("GITHUB_REF", ""))
    return parse_pull_request_number(match.group(1)) if match else 0


def _github_repository_url(
    repo: Optional[str], env: Mapping[str, str], remote_url: Optional[str] = None
) -> Optional[str]:
    remote_host, remote_path = parse_git_remote(env.get("BUILDKITE_REPO") or remote_url)
    # config.repo is only ever a bare repository name, so it cannot produce a
    # slug on its own; it is kept last for callers that pass a full owner/repo.
    repository = env.get("GITHUB_REPOSITORY") or remote_path or repo
    if not repository or "/" not in repository:
        return None
    server = (
        _http_url(env.get("GITHUB_SERVER_URL"))
        or (_http_url(f"https://{remote_host}") if remote_host else None)
        or "https://github.com"
    )
    return f"{server}/{repository.strip('/')}"


def _gitlab_project_url(
    repo: Optional[str], env: Mapping[str, str], remote_url: Optional[str] = None
) -> Optional[str]:
    project_url = _repository_url(env.get("CI_PROJECT_URL"))
    if not project_url:
        remote_host, remote_path = parse_git_remote(env.get("BUILDKITE_REPO") or remote_url)
        project_path = env.get("CI_PROJECT_PATH") or remote_path or repo
        server = (
            _http_url(env.get("CI_SERVER_URL"))
            or (_http_url(f"https://{remote_host}") if remote_host else None)
        )
        if server and project_path and "/" in project_path:
            project_url = f"{server}/{project_path.strip('/')}"
    return project_url


def _bitbucket_repository_url(
    repo: Optional[str], env: Mapping[str, str], remote_url: Optional[str] = None
) -> Optional[str]:
    remote_host, remote_path = parse_git_remote(remote_url)
    repository = env.get("BITBUCKET_REPO_FULL_NAME") or remote_path or repo
    if not repository or "/" not in repository:
        return None
    server = (
        _http_url(env.get("BITBUCKET_SERVER_URL"))
        or (_http_url(f"https://{remote_host}") if remote_host else None)
        or "https://bitbucket.org"
    )
    return f"{server}/{repository.strip('/')}"


def resolve_repository_url(
    scm: Optional[str],
    repo: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    remote_url: Optional[str] = None,
) -> Optional[str]:
    """Return the web URL of the scanned repository, such as ``https://github.com/owner/repo``.

    The CI environment wins, then the checkout's ``origin`` remote. ``None`` means the
    owner could not be determined: ``config.repo`` is the Socket repository slug,
    which has no owner, so a link built from it alone would point nowhere.
    """
    environment = env or {}
    provider = str(scm or "").lower()
    if provider == "github":
        return _github_repository_url(repo, environment, remote_url)
    if provider == "gitlab":
        return _gitlab_project_url(repo, environment, remote_url)
    if provider == "bitbucket":
        return _bitbucket_repository_url(repo, environment, remote_url)
    return None


def repository_owner(repository_url: Optional[str]) -> str:
    """Return everything before the repository name in ``repository_url``'s path.

    That is the owner on GitHub and Bitbucket, and the full group path on GitLab,
    where projects can be nested under subgroups.
    """
    if not repository_url:
        return ""
    path = urlparse(repository_url).path.strip("/")
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _github_url(number: int, repo: Optional[str], env: Mapping[str, str]) -> Optional[str]:
    repository_url = _github_repository_url(repo, env)
    return f"{repository_url}/pull/{number}" if repository_url else None


def _gitlab_url(number: int, repo: Optional[str], env: Mapping[str, str]) -> Optional[str]:
    project_url = _gitlab_project_url(repo, env)
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
    number = parse_pull_request_number(configured_number)

    if not configured_explicit and not number:
        if provider == "github":
            number = _github_number(environment)
        elif provider == "gitlab":
            number = parse_pull_request_number(environment.get("CI_MERGE_REQUEST_IID"))
        elif provider == "azure":
            number = (
                parse_pull_request_number(environment.get("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER")) or
                parse_pull_request_number(environment.get("SYSTEM_PULLREQUEST_PULLREQUESTID"))
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
