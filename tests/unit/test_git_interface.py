import logging
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from socketsecurity.core.git_interface import Git

CI_ENVIRONMENT_VARIABLES = (
    "BUILDKITE",
    "BUILDKITE_BRANCH",
    "BUILDKITE_COMMIT",
    "BUILDKITE_PIPELINE_DEFAULT_BRANCH",
    "BUILDKITE_PULL_REQUEST",
    "BUILDKITE_PULL_REQUEST_BASE_BRANCH",
    "GITHUB_BASE_REF",
    "GITHUB_EVENT_BEFORE",
    "GITHUB_EVENT_NAME",
    "GITHUB_HEAD_REF",
    "GITHUB_REF",
    "GITHUB_SHA",
    "CI_COMMIT_BRANCH",
    "CI_COMMIT_SHA",
    "CI_DEFAULT_BRANCH",
    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
    "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    "BITBUCKET_BRANCH",
    "BITBUCKET_COMMIT",
    "BITBUCKET_PR_DESTINATION_BRANCH",
    "BITBUCKET_PR_ID",
)


@pytest.fixture(autouse=True)
def clear_ci_environment(monkeypatch):
    for variable in CI_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(variable, raising=False)


def _git(path, *args):
    return subprocess.run(
        ["git", *args],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def pull_request_repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.name", "Socket Test")
    _git(path, "config", "user.email", "socket@example.com")
    (path / "README.md").write_text("base\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "base")
    _git(path, "checkout", "-b", "feature")
    (path / "package.json").write_text("{}\n", encoding="utf-8")
    _git(path, "add", "package.json")
    _git(path, "commit", "-m", "add manifest")
    return path


@pytest.mark.parametrize(
    ("environment", "expected_branch", "expected_source"),
    [
        (
            {
                "BUILDKITE": "true",
                "BUILDKITE_BRANCH": "feature",
                "BUILDKITE_PULL_REQUEST": "123",
                "BUILDKITE_PULL_REQUEST_BASE_BRANCH": "main",
            },
            "feature",
            "buildkite-pr",
        ),
        (
            {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_BASE_REF": "main",
                "GITHUB_HEAD_REF": "feature",
                "GITHUB_REF": "refs/pull/123/merge",
            },
            "feature",
            "github-pr",
        ),
        (
            {
                "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feature",
                "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
            },
            "feature",
            "gitlab-mr",
        ),
        (
            {
                "BITBUCKET_BRANCH": "feature",
                "BITBUCKET_PR_DESTINATION_BRANCH": "main",
                "BITBUCKET_PR_ID": "123",
            },
            "feature",
            "bitbucket-pr",
        ),
    ],
)
def test_pull_request_context_uses_local_refs_without_fetch(
        pull_request_repo, monkeypatch, mocker, caplog,
        environment, expected_branch, expected_source,
):
    head_sha = _git(pull_request_repo, "rev-parse", "HEAD")
    sha_variable = {
        "buildkite-pr": "BUILDKITE_COMMIT",
        "github-pr": "GITHUB_SHA",
        "gitlab-mr": "CI_COMMIT_SHA",
        "bitbucket-pr": "BITBUCKET_COMMIT",
    }[expected_source]
    environment[sha_variable] = head_sha
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    fetch = mocker.patch.object(
        Git,
        "_fetch_ref",
        side_effect=AssertionError("unexpected fetch"),
    )
    mocker.patch.object(Git, "ensure_safe_directory")

    with caplog.at_level(logging.INFO, logger="socketdev"):
        repository = Git(str(pull_request_repo))

    assert repository.branch == expected_branch
    assert repository.changed_files == ["package.json"]
    assert repository.is_default_branch is False
    fetch.assert_not_called()
    assert any(
        f"source={expected_source}" in record.message
        for record in caplog.records
    )
    assert any(
        "Git initialization completed" in record.message
        for record in caplog.records
    )


def test_buildkite_native_context_wins_over_github_compatibility_shims(
        pull_request_repo, monkeypatch, mocker
):
    head_sha = _git(pull_request_repo, "rev-parse", "HEAD")
    monkeypatch.setenv("BUILDKITE", "true")
    monkeypatch.setenv("BUILDKITE_BRANCH", "feature")
    monkeypatch.setenv("BUILDKITE_COMMIT", head_sha)
    monkeypatch.setenv("BUILDKITE_PULL_REQUEST", "123")
    monkeypatch.setenv("BUILDKITE_PULL_REQUEST_BASE_BRANCH", "main")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_BASE_REF", "wrong-base")
    monkeypatch.setenv("GITHUB_HEAD_REF", "wrong-head")
    mocker.patch.object(
        Git,
        "_fetch_ref",
        side_effect=AssertionError("unexpected fetch"),
    )
    mocker.patch.object(Git, "ensure_safe_directory")

    repository = Git(str(pull_request_repo))

    assert repository.changed_files == ["package.json"]


def test_regular_initialization_never_fetches_all(pull_request_repo, mocker):
    fetch = mocker.patch.object(
        Git,
        "_fetch_ref",
        side_effect=AssertionError("unexpected fetch"),
    )
    mocker.patch.object(Git, "ensure_safe_directory")

    repository = Git(str(pull_request_repo))

    assert repository.commit_str == _git(pull_request_repo, "rev-parse", "HEAD")
    assert repository.changed_files == ["package.json"]
    fetch.assert_not_called()


def test_detached_head_uses_buildkite_branch_and_commit(pull_request_repo, monkeypatch, mocker):
    head_sha = _git(pull_request_repo, "rev-parse", "HEAD")
    _git(pull_request_repo, "checkout", "--detach", head_sha)
    monkeypatch.setenv("BUILDKITE", "true")
    monkeypatch.setenv("BUILDKITE_BRANCH", "feature")
    monkeypatch.setenv("BUILDKITE_COMMIT", head_sha)
    monkeypatch.setenv("BUILDKITE_PULL_REQUEST", "123")
    monkeypatch.setenv("BUILDKITE_PULL_REQUEST_BASE_BRANCH", "main")
    mocker.patch.object(
        Git,
        "_fetch_ref",
        side_effect=AssertionError("unexpected fetch"),
    )
    mocker.patch.object(Git, "ensure_safe_directory")

    repository = Git(str(pull_request_repo))

    assert repository.commit_str == head_sha
    assert repository.branch == "feature"
    assert repository.changed_files == ["package.json"]


def test_missing_base_ref_fetches_only_that_ref(
        pull_request_repo, monkeypatch, mocker, caplog
):
    head_sha = _git(pull_request_repo, "rev-parse", "HEAD")
    monkeypatch.setenv("BUILDKITE_BRANCH", "feature")
    monkeypatch.setenv("BUILDKITE_COMMIT", head_sha)
    monkeypatch.setenv("BUILDKITE_PULL_REQUEST", "123")
    monkeypatch.setenv("BUILDKITE_PULL_REQUEST_BASE_BRANCH", "remote-main")
    mocker.patch.object(Git, "ensure_safe_directory")
    base_sha = _git(pull_request_repo, "rev-parse", "main")
    fetch = mocker.patch.object(Git, "_fetch_ref", return_value=base_sha)

    with caplog.at_level(logging.INFO, logger="socketdev"):
        repository = Git(str(pull_request_repo))

    fetch.assert_called_once_with(
        "remote-main",
        "Buildkite pull-request base ref missing",
    )
    assert repository.changed_files == ["package.json"]


def test_targeted_fetch_never_uses_all():
    repository = Git.__new__(Git)
    repository.repo = MagicMock()
    repository._fetched_ref_commits = {}
    main_sha = "a" * 40
    repository.repo.commit.return_value = SimpleNamespace(hexsha=main_sha)

    result = repository._fetch_ref("main", "test")

    repository.repo.git.fetch.assert_called_once_with("origin", "main")
    assert "--all" not in repository.repo.git.fetch.call_args.args
    assert result == main_sha


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, False), ("", False), ("false", False), ("False", False), ("0", True), ("123", True)],
)
def test_buildkite_pull_request_detection(value, expected):
    assert Git._is_buildkite_pull_request(value) is expected
