import pytest

from socketsecurity.core.scm.github import Github, GithubConfig

CONTEXT_VARIABLES = (
    "BUILDKITE",
    "BUILDKITE_BRANCH",
    "BUILDKITE_BUILD_CHECKOUT_PATH",
    "BUILDKITE_BUILD_CREATOR",
    "BUILDKITE_COMMIT",
    "BUILDKITE_MESSAGE",
    "BUILDKITE_PIPELINE_DEFAULT_BRANCH",
    "BUILDKITE_PULL_REQUEST",
    "BUILDKITE_PULL_REQUEST_REPO",
    "BUILDKITE_REPO",
    "DEFAULT_BRANCH",
    "EVENT_ACTION",
    "GH_API_TOKEN",
    "GITHUB_ACTOR",
    "GITHUB_API_URL",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_OWNER",
    "GITHUB_SHA",
    "GITHUB_WORKSPACE",
    "PR_NUMBER",
)


@pytest.fixture(autouse=True)
def clear_context(monkeypatch):
    for variable in CONTEXT_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("GH_API_TOKEN", "test-token")


def test_github_config_uses_native_buildkite_pull_request_context(monkeypatch):
    values = {
        "BUILDKITE": "true",
        "BUILDKITE_BRANCH": "feature/socket",
        "BUILDKITE_BUILD_CHECKOUT_PATH": "/workspace/repo",
        "BUILDKITE_BUILD_CREATOR": "octocat",
        "BUILDKITE_COMMIT": "a" * 40,
        "BUILDKITE_MESSAGE": "Update dependencies",
        "BUILDKITE_PIPELINE_DEFAULT_BRANCH": "main",
        "BUILDKITE_PULL_REQUEST": "123",
        "BUILDKITE_PULL_REQUEST_REPO": "git@github.com:acme/widgets.git",
        "BUILDKITE_REPO": "git@github.com:acme/widgets.git",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    config = GithubConfig.from_env()

    assert config.sha == "a" * 40
    assert config.api_url == "https://api.github.com"
    assert config.ref_type == "branch"
    assert config.event_name == "pull_request"
    assert config.event_action == "synchronize"
    assert config.workspace == "/workspace/repo"
    assert config.owner == "acme"
    assert config.repository == "widgets"
    assert config.ref_name == "feature/socket"
    assert config.pr_number == "123"
    assert config.commit_message == "Update dependencies"
    assert config.actor == "octocat"
    assert config.is_default_branch is False
    assert Github(client=object(), config=config).check_event_type() == "diff"


def test_buildkite_non_pr_build_uses_push_and_default_branch(monkeypatch):
    values = {
        "BUILDKITE": "true",
        "BUILDKITE_BRANCH": "main",
        "BUILDKITE_COMMIT": "b" * 40,
        "BUILDKITE_PIPELINE_DEFAULT_BRANCH": "main",
        "BUILDKITE_PULL_REQUEST": "false",
        "BUILDKITE_REPO": "https://github.com/acme/widgets.git",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    config = GithubConfig.from_env()

    assert config.event_name == "push"
    assert config.pr_number is None
    assert config.owner == "acme"
    assert config.repository == "widgets"
    assert config.is_default_branch is True
    assert Github(client=object(), config=config).check_event_type() == "main"


@pytest.mark.parametrize(
    "branch_variables",
    [
        {},
        {"BUILDKITE_BRANCH": "feature/socket"},
        {"BUILDKITE_PIPELINE_DEFAULT_BRANCH": "main"},
    ],
)
def test_buildkite_default_branch_requires_a_matching_branch_name(
        monkeypatch, branch_variables
):
    """Absent branch context must not be read as 'this build is the default branch'."""
    monkeypatch.setenv("BUILDKITE", "true")
    for name, value in branch_variables.items():
        monkeypatch.setenv(name, value)

    config = GithubConfig.from_env()

    assert config.is_default_branch is False
    assert config.default_branch is False


def test_explicit_github_values_take_priority_in_buildkite(monkeypatch):
    values = {
        "BUILDKITE": "true",
        "BUILDKITE_BRANCH": "buildkite-branch",
        "BUILDKITE_COMMIT": "b" * 40,
        "BUILDKITE_PULL_REQUEST": "123",
        "BUILDKITE_REPO": "git@github.com:buildkite/repository.git",
        "EVENT_ACTION": "opened",
        "GITHUB_API_URL": "https://github.example/api/v3",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REF_NAME": "github-branch",
        "GITHUB_REF_TYPE": "branch",
        "GITHUB_REPOSITORY": "github/repository",
        "GITHUB_SHA": "c" * 40,
        "GITHUB_WORKSPACE": "/github/workspace",
        "PR_NUMBER": "456",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    config = GithubConfig.from_env()

    assert config.sha == "c" * 40
    assert config.api_url == "https://github.example/api/v3"
    assert config.workspace == "/github/workspace"
    assert config.owner == "github"
    assert config.repository == "repository"
    assert config.ref_name == "github-branch"
    assert config.pr_number == "456"
    assert config.event_action == "opened"


@pytest.mark.parametrize(
    ("repository_url", "expected"),
    [
        ("git@github.com:acme/widgets.git", ("acme", "widgets")),
        ("https://github.com/acme/widgets.git", ("acme", "widgets")),
        ("ssh://git@github.com/acme/widgets.git", ("acme", "widgets")),
        ("", ("", "")),
        ("not-a-repository", ("", "")),
    ],
)
def test_buildkite_repository_url_parsing(monkeypatch, repository_url, expected):
    monkeypatch.setenv("BUILDKITE_REPO", repository_url)

    assert GithubConfig._repository_from_buildkite() == expected


def test_buildkite_pipeline_repository_wins_over_pull_request_fork(monkeypatch):
    monkeypatch.setenv("BUILDKITE_REPO", "git@github.com:acme/widgets.git")
    monkeypatch.setenv(
        "BUILDKITE_PULL_REQUEST_REPO",
        "git@github.com:contributor/widgets.git",
    )

    assert GithubConfig._repository_from_buildkite() == ("acme", "widgets")
