import subprocess

import pytest

from socketsecurity.config import (
    MAX_COMMIT_MESSAGE_LENGTH,
    CliConfig,
    truncate_commit_message,
)
from socketsecurity.socketcli import apply_git_context


def _git(path, *args):
    return subprocess.run(
        ["git", *args],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def repo_with_large_commit_message(tmp_path):
    """A checkout whose HEAD commit message is far larger than the cap (~14 KB)."""
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.name", "Socket Test")
    _git(path, "config", "user.email", "socket@example.com")
    (path / "package.json").write_text("{}\n", encoding="utf-8")
    _git(path, "add", "package.json")
    _git(path, "commit", "-m", "Release notes\n\n" + ("- bumped a dependency\n" * 700))
    return path


class TestTruncateCommitMessage:
    def test_none_passes_through(self):
        assert truncate_commit_message(None) is None

    def test_empty_passes_through(self):
        assert truncate_commit_message("") == ""

    def test_under_limit_is_unchanged(self):
        msg = "a normal short commit message"
        assert truncate_commit_message(msg) == msg

    def test_at_limit_is_unchanged(self):
        msg = "a" * MAX_COMMIT_MESSAGE_LENGTH
        assert truncate_commit_message(msg) == msg

    def test_over_limit_is_capped(self):
        assert truncate_commit_message("a" * 14_000) == "a" * MAX_COMMIT_MESSAGE_LENGTH


class TestCliConfigInvariant:
    def test_direct_construction_is_capped(self):
        config = CliConfig(api_token="test", repo="widgets", commit_message="a" * 14_000)
        assert config.commit_message == "a" * MAX_COMMIT_MESSAGE_LENGTH

    def test_config_file_value_is_capped(self, tmp_path):
        config_file = tmp_path / "socketcli.json"
        config_file.write_text('{"commit_message": "%s"}' % ("a" * 14_000), encoding="utf-8")
        config = CliConfig.from_args(["--api-token", "test", "--config", str(config_file)])
        assert config.commit_message == "a" * MAX_COMMIT_MESSAGE_LENGTH


class TestGitBackfill:
    def test_message_read_from_git_is_capped(self, repo_with_large_commit_message):
        config = CliConfig(api_token="test", repo=None, target_path=str(repo_with_large_commit_message))
        assert config.commit_message is None

        is_repo, git_repo = apply_git_context(config)

        assert is_repo is True
        # The repository really does carry an oversized message; the cap is what keeps it
        # out of the full-scan query string.
        assert len(git_repo.commit_message) > 14_000
        assert len(config.commit_message) == MAX_COMMIT_MESSAGE_LENGTH
        assert config.commit_message == git_repo.commit_message[:MAX_COMMIT_MESSAGE_LENGTH]

    def test_explicit_message_is_not_overwritten_by_git(self, repo_with_large_commit_message):
        config = CliConfig(
            api_token="test",
            repo=None,
            target_path=str(repo_with_large_commit_message),
            commit_message="explicit message",
        )

        apply_git_context(config)

        assert config.commit_message == "explicit message"

    def test_non_repo_path_reports_no_repo(self, tmp_path):
        config = CliConfig(api_token="test", repo=None, target_path=str(tmp_path))

        is_repo, git_repo = apply_git_context(config)

        assert is_repo is False
        assert git_repo is None
        assert config.ignore_commit_files is True
