import logging
import socket
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from git import Repo

from socketsecurity.core import git_interface
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
    "GITHUB_EVENT_PATH",
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
    remote_lookup = mocker.patch.object(
        Git,
        "_default_branch_from_remote",
        side_effect=AssertionError("unexpected remote default-branch lookup"),
    )
    mocker.patch.object(Git, "ensure_safe_directory")

    with caplog.at_level(logging.INFO, logger="socketdev"):
        repository = Git(str(pull_request_repo))

    assert repository.branch == expected_branch
    assert repository.changed_files == ["package.json"]
    assert repository.is_default_branch is False
    fetch.assert_not_called()
    remote_lookup.assert_not_called()
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


@pytest.fixture
def commit_range_repo(tmp_path):
    """A manifest changes mid-range, then a source-only commit lands on top of it."""
    path = tmp_path / "range-repo"
    path.mkdir()
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.name", "Socket Test")
    _git(path, "config", "user.email", "socket@example.com")
    (path / "README.md").write_text("base\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "base")
    base_sha = _git(path, "rev-parse", "HEAD")

    _git(path, "checkout", "-b", "feature")
    (path / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    _git(path, "add", "pom.xml")
    _git(path, "commit", "-m", "add dependency")
    manifest_sha = _git(path, "rev-parse", "HEAD")

    (path / "App.java").write_text("class App {}\n", encoding="utf-8")
    _git(path, "add", "App.java")
    _git(path, "commit", "-m", "source only")
    return SimpleNamespace(path=path, base_sha=base_sha, manifest_sha=manifest_sha)


def test_head_commit_alone_misses_a_manifest_changed_earlier_in_the_range(
        commit_range_repo, mocker,
):
    mocker.patch.object(Git, "ensure_safe_directory")

    repository = Git(str(commit_range_repo.path))

    # Without a stated base the range is unknown, so only the tip commit is read.
    assert repository.changed_files == ["App.java"]


def test_explicit_base_commit_covers_the_whole_range(
        commit_range_repo, mocker, caplog,
):
    mocker.patch.object(Git, "ensure_safe_directory")

    with caplog.at_level(logging.INFO, logger="socketdev"):
        repository = Git(
            str(commit_range_repo.path),
            base_commit_sha=commit_range_repo.base_sha,
        )

    assert sorted(repository.changed_files) == ["App.java", "pom.xml"]
    assert any(
        "source=explicit-base-commit" in record.message
        for record in caplog.records
    )


def test_explicit_base_commit_does_not_require_merge_base(
        commit_range_repo, tmp_path, mocker,
):
    shallow_path = tmp_path / "shallow-range-repo"
    _git(
        tmp_path,
        "clone",
        "--depth=1",
        "--branch=feature",
        commit_range_repo.path.as_uri(),
        str(shallow_path),
    )
    mocker.patch.object(Git, "ensure_safe_directory")

    repository = Git(
        str(shallow_path),
        base_commit_sha=commit_range_repo.base_sha,
    )

    # Fetching the base supplies both endpoint trees but does not deepen the
    # feature history enough to calculate a merge base.
    merge_base = subprocess.run(
        ["git", "merge-base", commit_range_repo.base_sha, "HEAD"],
        cwd=shallow_path,
        capture_output=True,
        text=True,
    )
    assert merge_base.returncode != 0
    assert sorted(repository.changed_files) == ["App.java", "pom.xml"]


def test_explicit_base_commit_takes_precedence_over_ci_environment(
        commit_range_repo, monkeypatch, mocker, caplog,
):
    # The CI variables describe the whole branch; the explicit base describes only
    # the last commit. They disagree, so the winner is unambiguous in the result.
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature")
    mocker.patch.object(Git, "ensure_safe_directory")

    with caplog.at_level(logging.INFO, logger="socketdev"):
        repository = Git(
            str(commit_range_repo.path),
            base_commit_sha=commit_range_repo.manifest_sha,
        )

    assert repository.changed_files == ["App.java"]
    assert any(
        "source=explicit-base-commit" in record.message
        for record in caplog.records
    )


def test_unresolvable_base_commit_warns_and_falls_back(
        commit_range_repo, mocker, caplog,
):
    mocker.patch.object(Git, "ensure_safe_directory")
    fetch = mocker.patch.object(Git, "_fetch_ref", return_value=None)

    with caplog.at_level(logging.WARNING, logger="socketdev"):
        repository = Git(str(commit_range_repo.path), base_commit_sha="0" * 40)

    # Falling back silently would hide that the comparison lost most of its range.
    assert repository.changed_files == ["App.java"]
    assert any(
        "Could not resolve base commit" in record.message
        for record in caplog.records
    )
    fetch.assert_called_once()


@pytest.fixture
def single_branch_checkout(tmp_path):
    """A repo whose default branch is dev, checked out the way actions/checkout does."""
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-b", "dev")
    _git(source, "config", "user.name", "Socket Test")
    _git(source, "config", "user.email", "socket@example.com")
    (source / "package.json").write_text("{}\n", encoding="utf-8")
    _git(source, "add", "package.json")
    _git(source, "commit", "-m", "base")
    origin = tmp_path / "origin.git"
    _git(tmp_path, "clone", "--bare", str(source), str(origin))

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    _git(checkout, "init")
    _git(checkout, "remote", "add", "origin", str(origin))
    _git(checkout, "fetch", "--no-tags", "--depth=1", "origin", "+refs/heads/dev:refs/remotes/origin/dev")
    _git(checkout, "checkout", "-B", "dev", "refs/remotes/origin/dev")
    return checkout


def test_single_branch_checkout_detects_non_main_default_branch(
        single_branch_checkout, monkeypatch, mocker
):
    monkeypatch.setenv("GITHUB_REF", "refs/heads/dev")
    mocker.patch.object(Git, "ensure_safe_directory")

    repository = Git(str(single_branch_checkout))

    assert repository.get_default_branch_name() == "dev"
    assert repository.is_default_branch is True


def test_github_event_payload_supplies_default_branch(
        single_branch_checkout, tmp_path, monkeypatch, mocker
):
    event_path = tmp_path / "event.json"
    event_path.write_text('{"repository": {"default_branch": "dev"}}', encoding="utf-8")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/dev")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    mocker.patch.object(Git, "ensure_safe_directory")
    remote_lookup = mocker.patch.object(Git, "_default_branch_from_remote")

    repository = Git(str(single_branch_checkout))

    assert repository.is_default_branch is True
    remote_lookup.assert_not_called()


@pytest.mark.parametrize(
    ("branch_variable", "default_variable"),
    [
        ("CI_COMMIT_BRANCH", "CI_DEFAULT_BRANCH"),
        ("BUILDKITE_BRANCH", "BUILDKITE_PIPELINE_DEFAULT_BRANCH"),
    ],
)
def test_ci_default_branch_variable_skips_remote_lookup(
        single_branch_checkout, monkeypatch, mocker, branch_variable, default_variable
):
    monkeypatch.setenv(branch_variable, "dev")
    monkeypatch.setenv(default_variable, "dev")
    mocker.patch.object(Git, "ensure_safe_directory")
    remote_lookup = mocker.patch.object(Git, "_default_branch_from_remote")

    repository = Git(str(single_branch_checkout))

    assert repository.is_default_branch is True
    remote_lookup.assert_not_called()


def test_origin_head_wins_without_remote_lookup(single_branch_checkout, monkeypatch, mocker):
    _git(single_branch_checkout, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/dev")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/dev")
    mocker.patch.object(Git, "ensure_safe_directory")
    remote_lookup = mocker.patch.object(Git, "_default_branch_from_remote")

    repository = Git(str(single_branch_checkout))

    assert repository.is_default_branch is True
    remote_lookup.assert_not_called()


def test_feature_branch_in_single_branch_checkout_is_not_default(
        single_branch_checkout, monkeypatch, mocker
):
    monkeypatch.setenv("GITHUB_REF", "refs/heads/feature")
    mocker.patch.object(Git, "ensure_safe_directory")

    repository = Git(str(single_branch_checkout))

    assert repository.is_default_branch is False


@pytest.fixture
def stalled_http_remote():
    """An HTTP remote that completes the TCP handshake and never responds."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    yield f"http://127.0.0.1:{server.getsockname()[1]}/repo.git"
    server.close()


def test_stalled_remote_lookup_stops_at_timeout(
        single_branch_checkout, stalled_http_remote, monkeypatch
):
    _git(single_branch_checkout, "remote", "set-url", "origin", stalled_http_remote)
    monkeypatch.setattr(git_interface, "REMOTE_HEAD_TIMEOUT_SECONDS", 1)
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(variable, raising=False)
    repository = Git.__new__(Git)
    repository.repo = Repo(str(single_branch_checkout))

    started = time.monotonic()
    result = repository._default_branch_from_remote()

    assert result is None
    assert 1 <= time.monotonic() - started < 10


def test_remote_lookup_parses_branch_with_slash(mocker):
    process = MagicMock(returncode=0)
    process.communicate.return_value = ("ref: refs/heads/release/stable\tHEAD\n", "")
    mocker.patch.object(git_interface.subprocess, "Popen", return_value=process)
    repository = Git.__new__(Git)
    repository.repo = MagicMock(working_dir="/repo")

    assert repository._default_branch_from_remote() == "release/stable"


def test_windows_timeout_kills_the_whole_process_tree(monkeypatch, mocker):
    monkeypatch.setattr(git_interface, "IS_WINDOWS", True)
    run = mocker.patch.object(git_interface.subprocess, "run")
    process = MagicMock(pid=4321)

    Git._kill_process_tree(process)

    assert run.call_args.args[0] == ["taskkill", "/F", "/T", "/PID", "4321"]
    process.wait.assert_called_once()
