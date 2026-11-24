"""GitHub and GitLab event routing and the CLI outcomes for GitHub PR actions."""

import json
import logging
import sys
from contextlib import nullcontext
from unittest.mock import MagicMock, Mock

import pytest

from socketsecurity import socketcli
from socketsecurity.core.classes import Diff, Issue
from socketsecurity.core.scm.github import (
    PULL_REQUEST_SCAN_ACTIONS,
    Github,
    GithubConfig,
)
from socketsecurity.core.scm.gitlab import Gitlab, GitlabConfig
from socketsecurity.core.scm_comments import Comments

CONTEXT_VARIABLES = (
    "BUILDKITE",
    "BUILDKITE_PULL_REQUEST",
    "DEFAULT_BRANCH",
    "EVENT_ACTION",
    "CI_MERGE_REQUEST_IID",
    "CI_PIPELINE_SOURCE",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_REPOSITORY",
    "PR_NUMBER",
    "SOCKET_SECURITY_API_KEY",
    "SOCKET_SECURITY_API_TOKEN",
    "SOCKET_API_KEY",
    "SOCKET_API_TOKEN",
)


@pytest.fixture(autouse=True)
def clear_context(monkeypatch):
    for variable in CONTEXT_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("GH_API_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/repo")


def _github(monkeypatch, event_name, action=None, pr_number="7"):
    if event_name is not None:
        monkeypatch.setenv("GITHUB_EVENT_NAME", event_name)
    if action is not None:
        monkeypatch.setenv("EVENT_ACTION", action)
    return Github(client=object(), config=GithubConfig.from_env(pr_number=pr_number))


def _skip_warnings(scm, caplog) -> list[str]:
    with (
        caplog.at_level(logging.INFO, logger="socketdev"),
        pytest.raises(SystemExit) as result,
    ):
        scm.check_event_type()
    assert result.value.code == 0
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


@pytest.mark.parametrize(
    "action", ["opened", "synchronize", "reopened", "ready_for_review", "Reopened"]
)
def test_pull_request_actions_that_change_the_head_result_are_scanned(
    monkeypatch, action
):
    assert _github(monkeypatch, "pull_request", action).check_event_type() == "diff"


def test_scanned_actions_are_the_documented_set():
    assert PULL_REQUEST_SCAN_ACTIONS == (
        "opened",
        "synchronize",
        "reopened",
        "ready_for_review",
    )


@pytest.mark.parametrize(
    "event_name, pr_number, expected",
    [
        ("push", None, "main"),
        ("push", "7", "diff"),
        ("workflow_dispatch", None, "main"),
        ("workflow_dispatch", "7", "diff"),
        ("issue_comment", "7", "comment"),
    ],
)
def test_other_handled_events_are_unchanged(
    monkeypatch, event_name, pr_number, expected
):
    github = _github(monkeypatch, event_name, pr_number=pr_number)
    assert github.check_event_type() == expected


@pytest.mark.parametrize("action", ["closed", "labeled", "edited"])
def test_other_pull_request_actions_skip_with_a_warning(monkeypatch, caplog, action):
    warnings = _skip_warnings(_github(monkeypatch, "pull_request", action), caplog)

    assert any(
        f"'{action}' is not scanned" in m and "No scan ran" in m for m in warnings
    )


@pytest.mark.parametrize("has_payload", [False, True])
def test_missing_pull_request_action_says_it_could_not_be_determined(
    monkeypatch, caplog, tmp_path, has_payload
):
    if has_payload:
        event_path = tmp_path / "event.json"
        event_path.write_text("{}", encoding="utf-8")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    warnings = _skip_warnings(_github(monkeypatch, "pull_request"), caplog)

    assert any(
        "Could not determine the pull_request action" in m and "No scan ran" in m
        for m in warnings
    )
    assert not any("is not scanned" in m for m in warnings)


def test_missing_event_name_says_it_could_not_be_determined(monkeypatch, caplog):
    warnings = _skip_warnings(_github(monkeypatch, None), caplog)

    assert any(
        "GITHUB_EVENT_NAME is not set" in m and "No scan ran" in m for m in warnings
    )


@pytest.mark.parametrize(
    "event_name, expected",
    [
        ("pull_request_target", "runs in the base repository context"),
        ("merge_group", "A required merge queue check must scan the merge group commit"),
        ("schedule", "'schedule' is not scanned"),
    ],
)
def test_unscanned_events_skip_with_a_warning(
    monkeypatch, caplog, event_name, expected
):
    warnings = _skip_warnings(_github(monkeypatch, event_name, "opened"), caplog)

    assert any(expected in message and "No scan ran" in message for message in warnings)
    if event_name == "schedule":
        assert any("issue_comment (ignore commands)" in message for message in warnings)


def _gitlab(monkeypatch, pipeline_source):
    monkeypatch.setenv("GITLAB_TOKEN", "test-token")
    if pipeline_source is not None:
        monkeypatch.setenv("CI_PIPELINE_SOURCE", pipeline_source)
    return Gitlab(client=object(), config=GitlabConfig.from_env())


@pytest.mark.parametrize(
    "pipeline_source, expected",
    [
        ("schedule", "'schedule' is not scanned"),
        (None, "CI_PIPELINE_SOURCE is not set"),
    ],
)
def test_gitlab_skipped_sources_warn(monkeypatch, caplog, pipeline_source, expected):
    warnings = _skip_warnings(_gitlab(monkeypatch, pipeline_source), caplog)

    assert any(expected in message and "No scan ran" in message for message in warnings)


def _blocking_alert() -> Issue:
    return Issue(
        pkg_name="lodash",
        pkg_version="4.17.11",
        pkg_type="npm",
        severity="critical",
        title="Critical CVE",
        description="",
        type="criticalCVE",
        url="https://socket.dev/test",
        manifests="package.json",
        props={},
        key="key",
        purl="pkg:npm/lodash@4.17.11",
        error=True,
        warn=False,
        ignore=False,
        monitor=False,
    )


@pytest.mark.parametrize(
    "action, has_blocker, scanned, expected_exit",
    [
        ("reopened", True, True, 1),
        ("reopened", False, True, 0),
        ("ready_for_review", True, True, 1),
        ("ready_for_review", False, True, 0),
        ("synchronize", True, True, 1),
        ("closed", True, False, 0),
    ],
)
def test_pull_request_payload_drives_scan_and_exit(
    monkeypatch, tmp_path, action, has_blocker, scanned, expected_exit
):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "socketcli",
            "--api-token",
            "test",
            "--scm",
            "github",
            "--strict-blocking",
            "--repo",
            "repo",
            "--branch",
            "feature",
            "--pr-number",
            "7",
            "--files",
            '["package.json"]',
        ],
    )
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"action": action}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("DEFAULT_BRANCH", "false")

    existing_alerts = [_blocking_alert()] if has_blocker else []
    diff = Diff(id="scan", new_alerts=[], unchanged_alerts=existing_alerts)
    diff.diff_url = "https://socket.dev/diff"
    monkeypatch.setattr(
        Github,
        "get_comments_for_pr",
        lambda self: Comments.check_for_socket_comments({}),
    )
    posted = Mock()
    monkeypatch.setattr(Github, "add_socket_comments", posted)
    monkeypatch.setattr(Github, "handle_ignore_reactions", Mock())
    sdk = MagicMock()
    sdk.org.get.return_value = {"organizations": {"org-id": {"slug": "acme"}}}
    monkeypatch.setattr(socketcli, "build_socket_sdk", Mock(return_value=sdk))
    monkeypatch.setattr(socketcli, "CliClient", Mock(return_value=Mock()))
    monkeypatch.setattr(
        socketcli, "StreamingLogs", lambda **kwargs: nullcontext(Mock())
    )
    monkeypatch.setattr(socketcli, "apply_git_context", lambda config: (False, None))
    scan = Mock(return_value=diff)
    monkeypatch.setattr(socketcli.Core, "create_new_diff", scan)
    full_scan = Mock()
    monkeypatch.setattr(socketcli.Core, "create_full_scan_with_report_url", full_scan)
    monkeypatch.setattr(socketcli.Core, "has_manifest_files", Mock(return_value=True))
    monkeypatch.setattr(socketcli.OutputHandler, "handle_output", Mock())

    with pytest.raises(SystemExit) as result:
        socketcli.cli()

    assert result.value.code == expected_exit
    full_scan.assert_not_called()
    assert scan.called is scanned
    assert posted.called is scanned
    if scanned:
        scan.assert_called_once()
        posted.assert_called_once()
        assert posted.call_args.args[3] is has_blocker
