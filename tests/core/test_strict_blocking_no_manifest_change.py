"""Scan routing and policy enforcement when no supported manifest changed."""

import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from socketsecurity import socketcli
from socketsecurity.core import Core
from socketsecurity.core.classes import Diff, Issue
from socketsecurity.core.scm.github import Github
from socketsecurity.core.scm.gitlab import Gitlab
from tests.core.test_existing_alerts import (
    BUCKETS,
    HANDLEBARS_CRITICAL_ADVISORIES,
    _cve_alert,
    _diff_artifact,
    _scan_artifact,
    _stream_through_sdk,
)

TOKEN_VARS = (
    "SOCKET_SECURITY_API_KEY",
    "SOCKET_SECURITY_API_TOKEN",
    "SOCKET_API_KEY",
    "SOCKET_API_TOKEN",
    "GH_API_TOKEN",
    "GITLAB_TOKEN",
    "CI_JOB_TOKEN",
    "CI_MERGE_REQUEST_IID",
)
STRICT_COMPARISON_LOG = "--strict-blocking compares the configured scan scope"
POLICIES = [
    pytest.param([], 3, id="default"),
    pytest.param(["--exit-code-on-api-error", "100"], 100, id="remap"),
    pytest.param(["--disable-blocking"], 0, id="nonblocking"),
]
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
    monkeypatch.setattr(
        socketcli, "StreamingLogs", lambda **kwargs: nullcontext(Mock())
    )
    git_repo = SimpleNamespace(
        changed_files=["README.md"], is_default_branch=False, remote_url=None
    )
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
        lambda self, files: any(
            f.endswith(("package.json", "package-lock.json")) for f in files
        ),
    )
    monkeypatch.setattr(Core, "find_files", Mock(return_value=["package.json"]))
    diff = Diff(id="compared")
    create_new_diff = Core.create_new_diff
    compare = Mock(return_value=diff)
    full_scan = Mock(return_value=Diff(id="full", report_url="", diff_url=""))
    monkeypatch.setattr(Core, "create_new_diff", compare)
    monkeypatch.setattr(Core, "create_full_scan_with_report_url", full_scan)
    monkeypatch.setattr(socketcli.OutputHandler, "handle_output", Mock())

    def run(flags=(), *, git=True):
        in_git_repo["value"] = git
        argv = [
            "socketcli",
            "--api-token",
            "test",
            "--repo",
            "repo",
            "--branch",
            "feature",
            "--integration",
            "api",
            *flags,
        ]
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as result:
            socketcli.cli()
        return result.value.code

    return SimpleNamespace(
        sdk=sdk,
        git_repo=git_repo,
        diff=diff,
        create_new_diff=create_new_diff,
        compare=compare,
        full_scan=full_scan,
        run=run,
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

    assert (
        cli_runtime.run(["--enable-diff", "--strict-blocking", "--disable-blocking"])
        == 0
    )
    cli_runtime.compare.assert_called_once()


@pytest.mark.parametrize("mode, git", MODES)
def test_without_strict_blocking_the_full_scan_fallback_is_unchanged(
    cli_runtime, mode, git
):
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


@pytest.fixture
def comparison(cli_runtime, monkeypatch):
    monkeypatch.setattr(Core, "create_new_diff", cli_runtime.create_new_diff)
    monkeypatch.setattr(Core, "get_org_id_slug", Mock(return_value=("org-id", "acme")))
    monkeypatch.setattr(
        Core, "resolve_base_full_scan_id", Mock(return_value="baseline")
    )
    upload = Mock(return_value=SimpleNamespace(id="head"))
    monkeypatch.setattr(Core, "create_full_scan", upload)
    monkeypatch.setattr(
        Core, "find_files", Mock(return_value=["package.json", "package-lock.json"])
    )
    cli_runtime.sdk.diffscans.create_from_ids.return_value = {
        "diff_scan": {"id": "comparison"}
    }
    cli_runtime.sdk.diffscans.get.return_value = {
        "diff_scan": {
            "artifacts": {
                **{bucket: [] for bucket in BUCKETS},
                "unchanged": [_diff_artifact("unchanged", "u1", "handlebars")],
            }
        }
    }
    return upload


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


@pytest.mark.parametrize(
    "event, extra",
    [
        pytest.param("pull_request", [], id="pull-request"),
        pytest.param(
            "pull_request", ["--ignore-commit-files"], id="ignore-commit-files"
        ),
        pytest.param("push", [], id="push-with-pr-number"),
    ],
)
def test_code_only_scan_with_pr_context_comments_on_each_existing_blocker(
    cli_runtime, github_pull_request, comparison, monkeypatch, event, extra
):
    monkeypatch.setenv("GITHUB_EVENT_NAME", event)
    resolved, *blocking = HANDLEBARS_CRITICAL_ADVISORIES[:3]
    alerts = [_cve_alert(*resolved, action="ignore")]
    alerts.extend(_cve_alert(ghsa, cve) for ghsa, cve in blocking)
    _stream_through_sdk(cli_runtime, _scan_artifact("u1", "handlebars", alerts))

    assert cli_runtime.run(["--scm", "github", "--strict-blocking", *extra]) == 1
    assert comparison.call_args.args[0] == ["package.json", "package-lock.json"]
    compare_params = cli_runtime.sdk.diffscans.create_from_ids.call_args.args[1]
    assert (compare_params["before"], compare_params["after"]) == ("baseline", "head")
    cli_runtime.sdk.fullscans.stream.assert_called_once()
    cli_runtime.full_scan.assert_not_called()
    github_pull_request.assert_called_once()
    security_comment, _, _, post_security, _ = github_pull_request.call_args.args
    assert post_security is True
    assert "Existing alerts (2)" in security_comment
    assert resolved[0].upper() not in security_comment
    for ghsa, _ in blocking:
        assert ghsa.upper() in security_comment


@pytest.mark.parametrize("policy, infrastructure_code", POLICIES)
@pytest.mark.parametrize("failure", ["incomplete-comparison", "missing-package"])
def test_code_only_pull_request_maps_comparison_failures(
    cli_runtime, github_pull_request, comparison, policy, infrastructure_code, failure
):
    if failure == "incomplete-comparison":
        cli_runtime.sdk.diffscans.get.return_value = {"diff_scan": {"incomplete": True}}
    else:
        cli_runtime.sdk.fullscans.stream.return_value = SimpleNamespace(
            success=True, artifacts={}
        )

    assert (
        cli_runtime.run(["--scm", "github", "--strict-blocking", *policy])
        == infrastructure_code
    )
    comparison.assert_called_once()
    cli_runtime.sdk.fullscans.stream_diff.assert_not_called()
    github_pull_request.assert_not_called()


def test_code_only_pull_request_without_strict_blocking_skips_the_comment(
    cli_runtime, github_pull_request
):
    assert cli_runtime.run(["--scm", "github"]) == 0
    cli_runtime.full_scan.assert_called_once()
    cli_runtime.compare.assert_not_called()
    github_pull_request.assert_not_called()


def test_branch_pipeline_still_creates_a_full_scan(cli_runtime, monkeypatch, caplog):
    monkeypatch.setenv("GH_API_TOKEN", "test")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/repo")
    monkeypatch.delenv("PR_NUMBER", raising=False)
    cli_runtime.full_scan.return_value = Diff(
        id="full", report_url="", diff_url="", new_alerts=[_existing_blocker()]
    )

    assert (
        cli_runtime.run(["--scm", "github", "--pr-number", "0", "--strict-blocking"])
        == 0
    )
    cli_runtime.full_scan.assert_called_once()
    cli_runtime.compare.assert_not_called()
    assert STRICT_COMPARISON_LOG not in caplog.text


def test_api_mode_default_branch_push_compares(cli_runtime):
    cli_runtime.git_repo.is_default_branch = True
    cli_runtime.diff.unchanged_alerts = [_existing_blocker()]

    assert cli_runtime.run(["--default-branch", "--strict-blocking"]) == 1
    cli_runtime.compare.assert_called_once()
    assert cli_runtime.compare.call_args.args[1].make_default_branch is True
    cli_runtime.full_scan.assert_not_called()


def test_comparison_is_logged_when_it_runs(cli_runtime, caplog):
    cli_runtime.diff.unchanged_alerts = [_existing_blocker()]

    cli_runtime.run(["--strict-blocking"])

    assert STRICT_COMPARISON_LOG in caplog.text


def test_skipped_pull_request_event_logs_no_comparison(
    cli_runtime, monkeypatch, caplog
):
    monkeypatch.setenv("GH_API_TOKEN", "test")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("EVENT_ACTION", "closed")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/repo")
    monkeypatch.setenv("PR_NUMBER", "7")

    assert cli_runtime.run(["--scm", "github", "--strict-blocking"]) == 0
    cli_runtime.compare.assert_not_called()
    cli_runtime.full_scan.assert_not_called()
    assert STRICT_COMPARISON_LOG not in caplog.text


@pytest.fixture
def gitlab_pipeline(cli_runtime, monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    monkeypatch.setenv("CI_PROJECT_NAME", "repo")
    monkeypatch.setenv("CI_DEFAULT_BRANCH", "main")
    monkeypatch.setenv("CI_API_V4_URL", "https://gitlab.example.com/api/v4")
    monkeypatch.setenv("CI_PROJECT_URL", "https://gitlab.example.com/acme/repo")
    monkeypatch.setattr(Gitlab, "get_comments_for_pr", Mock(return_value={}))
    add_comments = Mock()
    monkeypatch.setattr(Gitlab, "add_socket_comments", add_comments)
    return add_comments


def test_code_only_merge_request_comments_on_existing_blockers(
    cli_runtime, gitlab_pipeline, monkeypatch
):
    monkeypatch.setenv("CI_PIPELINE_SOURCE", "merge_request_event")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "7")
    monkeypatch.setenv("CI_MERGE_REQUEST_PROJECT_ID", "42")
    monkeypatch.setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "feature")
    cli_runtime.diff.unchanged_alerts = [_existing_blocker()]

    assert cli_runtime.run(["--scm", "gitlab", "--strict-blocking"]) == 1
    cli_runtime.compare.assert_called_once()
    cli_runtime.full_scan.assert_not_called()
    gitlab_pipeline.assert_called_once()
    security_comment, _, _, post_security, _ = gitlab_pipeline.call_args.args
    assert post_security is True
    assert "handlebars@4.0.11" in security_comment
    assert "Existing alerts" in security_comment


def test_gitlab_branch_pipeline_still_creates_a_full_scan(
    cli_runtime, gitlab_pipeline, monkeypatch, caplog
):
    monkeypatch.setenv("CI_PIPELINE_SOURCE", "push")
    cli_runtime.full_scan.return_value = Diff(
        id="full", report_url="", diff_url="", new_alerts=[_existing_blocker()]
    )

    assert cli_runtime.run(["--scm", "gitlab", "--strict-blocking"]) == 0
    cli_runtime.full_scan.assert_called_once()
    cli_runtime.compare.assert_not_called()
    gitlab_pipeline.assert_not_called()
    assert STRICT_COMPARISON_LOG not in caplog.text
