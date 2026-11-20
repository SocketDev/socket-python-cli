"""`--strict-blocking` on a change that touches no manifest.

Without `--ignore-commit-files`, the CLI reads the changed files to decide whether
to compare. When none is a supported manifest it used to create a full scan, turn
blocking off and warn that `--strict-blocking` needs diff mode, so a code-only pull
request passed even with existing blocking alerts. Under `--strict-blocking` the
comparison now runs anyway, the way `--ignore-commit-files` runs it. Runs without
the flag keep the full-scan fallback.
"""

import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from socketsecurity import socketcli
from socketsecurity.core import Core
from socketsecurity.core.classes import Diff, Issue, Package
from socketsecurity.core.scm.github import Github

TOKEN_VARS = (
    "SOCKET_SECURITY_API_KEY", "SOCKET_SECURITY_API_TOKEN", "SOCKET_API_KEY", "SOCKET_API_TOKEN",
    "GH_API_TOKEN", "GITLAB_TOKEN",
)
POLICIES = [
    pytest.param([], 3, id="default"),
    pytest.param(["--exit-code-on-api-error", "100"], 100, id="remap"),
    pytest.param(["--disable-blocking"], 0, id="nonblocking"),
]
# Each mode reaches the no-manifest fallback by a different path.
MODES = [
    pytest.param(["--enable-diff"], True, id="enable-diff"),
    pytest.param([], True, id="api-default"),
    pytest.param(["--files", '["src/index.js"]'], True, id="files-without-manifest"),
    pytest.param([], False, id="not-a-git-repo"),
]


def _existing_blocker() -> Issue:
    return Issue(
        pkg_name="handlebars",
        pkg_version="4.0.11",
        pkg_type="npm",
        severity="critical",
        title="Critical CVE",
        description="Prototype pollution",
        type="criticalCVE",
        url="https://socket.dev/npm/package/handlebars/overview/4.0.11",
        manifests="package-lock.json",
        props={"ghsaId": "GHSA-w457-6q6x-cgp9"},
        key="existing-key",
        purl="pkg:npm/handlebars@4.0.11",
        error=True,
        warn=False,
        ignore=False,
        monitor=False,
        suggestion="Upgrade handlebars",
        next_step_title="Next steps",
    )


@pytest.fixture
def cli_runtime(monkeypatch):
    for name in TOKEN_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BUILDKITE", "false")
    sdk = MagicMock()
    monkeypatch.setattr(socketcli, "build_socket_sdk", Mock(return_value=sdk))
    monkeypatch.setattr(socketcli, "CliClient", Mock())
    monkeypatch.setattr(socketcli, "StreamingLogs", lambda **kwargs: nullcontext(Mock()))
    git_repo = SimpleNamespace(changed_files=["README.md"], is_default_branch=False, remote_url=None)
    in_git_repo = {"value": True}

    def apply_git_context(config):
        if not in_git_repo["value"]:
            config.ignore_commit_files = True
            return False, None
        return True, git_repo

    monkeypatch.setattr(socketcli, "apply_git_context", apply_git_context)
    monkeypatch.setattr(
        Core,
        "has_manifest_files",
        lambda self, files: any(f.endswith(("package.json", "package-lock.json")) for f in files),
    )
    monkeypatch.setattr(Core, "find_files", Mock(return_value=["package.json"]))
    diff = Diff(id="compared")
    compare = Mock(return_value=diff)
    full_scan = Mock(return_value=Diff(id="full", report_url="", diff_url=""))
    monkeypatch.setattr(Core, "create_new_diff", compare)
    monkeypatch.setattr(Core, "create_full_scan_with_report_url", full_scan)
    monkeypatch.setattr(socketcli.OutputHandler, "handle_output", Mock())

    def run(flags=(), *, git=True):
        in_git_repo["value"] = git
        argv = [
            "socketcli", "--api-token", "test", "--repo", "repo", "--branch", "feature",
            "--integration", "api", *flags,
        ]
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as result:
            socketcli.cli()
        return result.value.code

    return SimpleNamespace(
        sdk=sdk, git_repo=git_repo, diff=diff, compare=compare, full_scan=full_scan, run=run,
    )


@pytest.mark.parametrize("mode, git", MODES)
def test_existing_blocker_fails_a_change_without_manifests(cli_runtime, mode, git):
    cli_runtime.diff.unchanged_alerts = [_existing_blocker()]

    assert cli_runtime.run([*mode, "--strict-blocking"], git=git) == 1
    cli_runtime.compare.assert_called_once()
    cli_runtime.full_scan.assert_not_called()


@pytest.mark.parametrize("mode, git", MODES)
def test_no_existing_blocker_passes_a_change_without_manifests(cli_runtime, mode, git):
    cli_runtime.diff.unchanged_alerts = [Issue(error=False, warn=True)]

    assert cli_runtime.run([*mode, "--strict-blocking"], git=git) == 0
    cli_runtime.compare.assert_called_once()
    cli_runtime.full_scan.assert_not_called()


def test_disable_blocking_still_wins(cli_runtime):
    cli_runtime.diff.unchanged_alerts = [_existing_blocker()]

    assert cli_runtime.run(["--enable-diff", "--strict-blocking", "--disable-blocking"]) == 0
    cli_runtime.compare.assert_called_once()


@pytest.mark.parametrize("mode, git", MODES)
def test_without_strict_blocking_the_full_scan_fallback_is_unchanged(cli_runtime, mode, git):
    cli_runtime.full_scan.return_value = Diff(
        id="full", report_url="", diff_url="", new_alerts=[_existing_blocker()]
    )

    assert cli_runtime.run(mode, git=git) == 0
    cli_runtime.full_scan.assert_called_once()
    cli_runtime.compare.assert_not_called()


def test_no_fallback_warning_under_strict_blocking(cli_runtime, caplog):
    cli_runtime.diff.unchanged_alerts = [_existing_blocker()]

    cli_runtime.run(["--enable-diff", "--strict-blocking"])

    assert "Falling back to full scan mode" not in caplog.text
    assert "only supported in diff mode" not in caplog.text


def test_changed_manifest_still_compares(cli_runtime):
    cli_runtime.git_repo.changed_files = ["package.json"]
    cli_runtime.diff.unchanged_alerts = [_existing_blocker()]

    assert cli_runtime.run(["--enable-diff", "--strict-blocking"]) == 1
    assert cli_runtime.run(["--enable-diff"]) == 0
    assert cli_runtime.compare.call_count == 2
    cli_runtime.full_scan.assert_not_called()


@pytest.mark.parametrize("policy, infrastructure_code", POLICIES)
def test_unreadable_existing_alerts_use_the_infrastructure_code(cli_runtime, policy, infrastructure_code):
    package = Package(id="pkg", type="npm", name="pkg", version="1", score={}, alerts=[])
    cli_runtime.sdk.fullscans.stream.return_value = SimpleNamespace(success=True, artifacts={})

    def compare(*args, **kwargs):
        core = Core.__new__(Core)
        core.sdk = cli_runtime.sdk
        core.config = SimpleNamespace(org_slug="acme")
        core.add_existing_alerts_from_full_scan({package.id: package}, "new")

    cli_runtime.compare.side_effect = compare

    assert cli_runtime.run(["--enable-diff", "--strict-blocking", *policy]) == infrastructure_code


@pytest.fixture
def github_pull_request(cli_runtime, monkeypatch):
    monkeypatch.setenv("GH_API_TOKEN", "test")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("EVENT_ACTION", "synchronize")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/repo")
    monkeypatch.setenv("PR_NUMBER", "7")
    monkeypatch.setattr(Github, "get_comments_for_pr", Mock(return_value={}))
    add_comments = Mock()
    monkeypatch.setattr(Github, "add_socket_comments", add_comments)
    return add_comments


def test_code_only_pull_request_comments_on_existing_blockers(cli_runtime, github_pull_request):
    cli_runtime.diff.unchanged_alerts = [_existing_blocker()]

    assert cli_runtime.run(["--scm", "github", "--strict-blocking"]) == 1
    cli_runtime.compare.assert_called_once()
    github_pull_request.assert_called_once()
    security_comment, _, _, post_security, _ = github_pull_request.call_args.args
    assert post_security is True
    assert "handlebars@4.0.11" in security_comment
    assert "Existing alerts" in security_comment


def test_code_only_pull_request_without_strict_blocking_skips_the_comment(
    cli_runtime, github_pull_request
):
    assert cli_runtime.run(["--scm", "github"]) == 0
    cli_runtime.full_scan.assert_called_once()
    cli_runtime.compare.assert_not_called()
    github_pull_request.assert_not_called()


def test_branch_pipeline_still_creates_a_full_scan(cli_runtime, monkeypatch):
    # Non-PR SCM pipelines have no baseline; --strict-blocking does not change that.
    monkeypatch.setenv("GH_API_TOKEN", "test")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/repo")
    monkeypatch.delenv("PR_NUMBER", raising=False)

    assert cli_runtime.run(["--scm", "github", "--pr-number", "0", "--strict-blocking"]) == 0
    cli_runtime.full_scan.assert_called_once()
    cli_runtime.compare.assert_not_called()
