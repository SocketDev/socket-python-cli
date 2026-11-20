"""Which GitHub events and pull_request actions run a scan.

A skipped run exits 0, and GitHub doesn't define which run a required check uses
when the same job runs more than once on a commit, so skipping an action that a
workflow subscribes to can satisfy the check with a pass that never scanned
anything.
"""

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


def test_missing_pull_request_action_says_it_could_not_be_determined(
    monkeypatch, caplog
):
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
        ("pull_request_target", "runs against the base branch"),
        ("merge_group", "'merge_group' is not scanned"),
        ("schedule", "'schedule' is not scanned"),
    ],
)
def test_unscanned_events_skip_with_a_warning(
    monkeypatch, caplog, event_name, expected
):
    warnings = _skip_warnings(_github(monkeypatch, event_name, "opened"), caplog)

    assert any(expected in message and "No scan ran" in message for message in warnings)
    # issue_comment is handled, but it runs the ignore-command flow, not a scan.
    if event_name != "pull_request_target":
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
    "action, scanned, expected_exit",
    [
        ("reopened", True, 1),
        ("ready_for_review", True, 1),
        ("synchronize", True, 1),
        ("closed", False, 0),
    ],
)
def test_reopened_pull_request_blocks_like_synchronize(
    monkeypatch, action, scanned, expected_exit
):
    """A reopened PR with an existing blocker fails instead of passing unscanned."""
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
    monkeypatch.setenv("EVENT_ACTION", action)
    monkeypatch.setenv("DEFAULT_BRANCH", "false")

    diff = Diff(id="scan", new_alerts=[], unchanged_alerts=[_blocking_alert()])
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
    monkeypatch.setattr(socketcli.Core, "has_manifest_files", Mock(return_value=True))
    monkeypatch.setattr(socketcli.OutputHandler, "handle_output", Mock())

    with pytest.raises(SystemExit) as result:
        socketcli.cli()

    assert result.value.code == expected_exit
    assert scan.called is scanned
    assert posted.called is scanned
