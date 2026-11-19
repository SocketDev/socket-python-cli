"""Alerts on unchanged packages come from the full scan when the comparison omits them.

The cached diff-scans endpoint returns unchanged artifacts with an empty
``alerts`` list, so ``--strict-blocking`` had nothing to block on and passed.
The new full scan carries every package's alerts, so the CLI reads them from
there whenever an output needs them: ``--strict-blocking``, the GitLab security
report and FOSSA-format output.
"""
import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from socketdev.exceptions import APIFailure
from socketdev.fullscans import (
    FullScanParams,
    FullScanStreamResponse,
    StreamDiffResponse,
)

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.classes import Comment, Diff, Issue
from socketsecurity.core.messages import Messages
from socketsecurity.core.scm_comments import Comments
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.exit_codes import InfrastructureError
from socketsecurity.output import OutputHandler

BUCKETS = ("added", "removed", "unchanged", "replaced", "updated")


def _alert(key, action="error", alert_type="malware"):
    return {
        "key": key,
        "type": alert_type,
        "severity": "critical",
        "category": "supplyChainRisk",
        "props": {},
        "action": action,
    }


def _diff_artifact(diff_type, artifact_id, name, alerts=None):
    ref = {
        "direct": True,
        "manifestFiles": [{"file": "package.json", "start": 0, "end": 0}],
        "topLevelAncestors": [],
    }
    return {
        "diffType": diff_type,
        "type": "npm",
        "name": name,
        "version": "1.0.0",
        "id": artifact_id,
        "head": [ref],
        "base": [],
        "license": "MIT",
        "licenseDetails": [],
        "author": [],
        "size": 1,
        "score": {},
        "alerts": alerts or [],
    }


def _scan_artifact(artifact_id, name, alerts):
    return {
        "type": "npm",
        "name": name,
        "version": "1.0.0",
        "id": artifact_id,
        "direct": True,
        "manifestFiles": [{"file": "package.json", "start": 0, "end": 0}],
        "topLevelAncestors": [],
        "license": "MIT",
        "licenseDetails": [],
        "author": [],
        "size": 1,
        "score": {},
        "alerts": alerts,
    }


def _diff_response(**buckets):
    raw = json.loads((Path(__file__).parent.parent / "data/fullscans/diff/stream_diff.json").read_text())
    artifacts = {name: buckets.get(name, []) for name in BUCKETS}
    return StreamDiffResponse.from_dict({
        "success": raw["success"],
        "status": raw["status"],
        "data": {**raw["data"], "artifacts": artifacts},
    })


def _scan_response(*artifacts):
    return FullScanStreamResponse.from_dict({
        "success": True,
        "status": 200,
        "artifacts": {artifact["id"]: artifact for artifact in artifacts},
    })


@pytest.fixture
def core(mock_sdk_with_responses):
    core = Core(config=SocketConfig(api_key="test_key"), sdk=mock_sdk_with_responses)
    core.sdk.diffscans.create_from_ids.side_effect = Exception("diff-scans unavailable")
    core.sdk.fullscans.stream_diff.side_effect = None
    core.sdk.fullscans.stream.side_effect = None
    core.resolve_base_full_scan_id = Mock(return_value="head")
    core.create_full_scan = Mock(return_value=SimpleNamespace(id="new"))
    return core


def _run(core, *flags, unchanged_alerts=None, scan_alerts=None, scan_id="u1"):
    core.cli_config = CliConfig.from_args(["--api-token", "test", *flags])
    core.sdk.fullscans.stream_diff.return_value = _diff_response(
        added=[_diff_artifact("added", "a1", "alpha", [_alert("k1")])],
        unchanged=[_diff_artifact("unchanged", "u1", "gamma", unchanged_alerts)],
    )
    core.sdk.fullscans.stream.return_value = _scan_response(
        _scan_artifact("a1", "alpha", [_alert("k1")]),
        _scan_artifact(scan_id, "gamma", scan_alerts if scan_alerts is not None else [_alert("k3")]),
    )
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True
    return core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])


def _handler(strict_blocking=True):
    config = Mock(spec=CliConfig)
    config.disable_blocking = False
    config.strict_blocking = strict_blocking
    return OutputHandler(config, Mock())


def test_strict_blocking_reads_existing_alerts_from_the_full_scan(core):
    diff = _run(core, "--strict-blocking")

    assert [a.pkg_name for a in diff.unchanged_alerts] == ["gamma"]
    assert diff.unchanged_alerts[0].error
    core.sdk.fullscans.stream.assert_called_once()


def test_strict_blocking_fails_on_an_existing_blocking_alert(core):
    """The exit-0 case: the only blocking alert is on a package the change didn't touch."""
    core.cli_config = CliConfig.from_args(["--api-token", "test", "--strict-blocking"])
    core.sdk.fullscans.stream_diff.return_value = _diff_response(
        unchanged=[_diff_artifact("unchanged", "u1", "gamma")],
    )
    core.sdk.fullscans.stream.return_value = _scan_response(_scan_artifact("u1", "gamma", [_alert("k3")]))
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    diff = core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])

    assert diff.new_alerts == []
    assert not _handler(strict_blocking=True).report_pass(diff)


def test_existing_alerts_match_by_package_when_artifact_ids_differ(core):
    diff = _run(core, "--strict-blocking", scan_id="other-id")

    assert [a.pkg_name for a in diff.unchanged_alerts] == ["gamma"]


def test_existing_warnings_are_kept_and_ignored_alerts_are_not(core):
    diff = _run(
        core, "--strict-blocking",
        scan_alerts=[_alert("k3", action="warn"), _alert("k4", action="ignore", alert_type="envVars")],
    )

    assert [(a.pkg_name, a.warn, a.error) for a in diff.unchanged_alerts] == [("gamma", True, False)]


@pytest.mark.parametrize("flags", [("--enable-gitlab-security",), ("--legal-format", "fossa")])
def test_full_scope_reports_also_read_existing_alerts(core, flags):
    diff = _run(core, *flags)

    assert [a.pkg_name for a in diff.unchanged_alerts] == ["gamma"]


def test_no_extra_fetch_when_no_output_reads_existing_alerts(core):
    diff = _run(core)

    core.sdk.fullscans.stream.assert_not_called()
    assert diff.unchanged_alerts == []


def test_no_extra_fetch_when_the_comparison_already_has_existing_alerts(core):
    """The streaming comparison includes them, and so will diff-scans once the API does."""
    diff = _run(core, "--strict-blocking", unchanged_alerts=[_alert("k3")])

    core.sdk.fullscans.stream.assert_not_called()
    assert [a.pkg_name for a in diff.unchanged_alerts] == ["gamma"]


def test_failed_full_scan_fetch_fails_the_run(core):
    """Reporting no existing alerts after a failed fetch would let the run pass."""
    core.cli_config = CliConfig.from_args(["--api-token", "test", "--strict-blocking"])
    core.sdk.fullscans.stream_diff.return_value = _diff_response(
        unchanged=[_diff_artifact("unchanged", "u1", "gamma")],
    )
    core.sdk.fullscans.stream.return_value = FullScanStreamResponse.from_dict(
        {"success": False, "status": 500, "message": "boom"}
    )
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    with pytest.raises(APIFailure):
        core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])


@pytest.mark.parametrize("flags", [
    ("--strict-blocking",), ("--enable-gitlab-security",), ("--legal-format", "fossa"),
])
@pytest.mark.parametrize("response_kind", ["missing", "malformed", "empty"])
def test_incomplete_existing_alert_data_fails_the_run(core, flags, response_kind):
    """A successful response can still omit packages, including SDK parse failures."""
    core.cli_config = CliConfig.from_args(["--api-token", "test", *flags])
    core.sdk.fullscans.stream_diff.return_value = _diff_response(unchanged=[
        _diff_artifact("unchanged", "u1", "gamma"),
        _diff_artifact("unchanged", "u2", "delta"),
    ])
    artifacts = [_scan_artifact("u2", "delta", [])]
    if response_kind == "malformed":
        broken = _scan_artifact("u1", "gamma", [_alert("k3")])
        del broken["alerts"][0]["key"]
        artifacts.append(broken)
    elif response_kind == "empty":
        artifacts = []
    core.sdk.fullscans.stream.return_value = _scan_response(*artifacts)
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    with pytest.raises(InfrastructureError, match="unchanged packages.*full scan new"):
        core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])


def test_matched_package_without_alerts_is_a_clean_result(core):
    diff = _run(core, "--strict-blocking", scan_alerts=[])

    assert diff.unchanged_alerts == []
    core.sdk.fullscans.stream.assert_called_once()


# --- PR comment ------------------------------------------------------------------------


def _issue(name, error=True, warn=False):
    return Issue(
        pkg_type="npm",
        pkg_name=name,
        pkg_version="1.0.0",
        purl=f"{name}@1.0.0",
        type="malware",
        severity="critical",
        title="Known malware",
        description="Bad.",
        suggestion="Remove it.",
        url=f"https://socket.dev/npm/package/{name}",
        props={},
        key=f"key-{name}",
        error=error,
        warn=warn,
    )


def _comment_diff(new=(), existing=()):
    diff = Diff()
    diff.new_alerts = list(new)
    diff.unchanged_alerts = list(existing)
    diff.diff_url = "https://socket.dev/diff"
    diff.report_url = "https://socket.dev/report"
    return diff


def _config(strict_blocking=True):
    return SimpleNamespace(strict_blocking=strict_blocking, disable_ignore=False, scm="github")


def test_pr_comment_lists_existing_alerts_under_strict_blocking():
    diff = _comment_diff(new=[_issue("alpha")], existing=[_issue("gamma", error=False, warn=True), _issue("delta")])

    comment = Messages.security_comment_template(diff, _config())

    assert "Existing alerts (2)" in comment
    assert "fails the run on the 1 with a **Block** action" in comment
    # Blocking existing alerts come first.
    assert comment.index("delta@1.0.0 - Known malware") < comment.index("gamma@1.0.0 - Known malware")
    assert comment.index("alpha@1.0.0") < comment.index("Existing alerts")


def test_pr_comment_leaves_existing_alerts_out_without_strict_blocking():
    diff = _comment_diff(new=[_issue("alpha")], existing=[_issue("gamma")])

    comment = Messages.security_comment_template(diff, _config(strict_blocking=False))

    assert "Existing alerts" not in comment
    assert "gamma" not in comment


def test_pr_comment_with_only_existing_alerts_says_nothing_new():
    diff = _comment_diff(existing=[_issue("gamma")])

    comment = Messages.security_comment_template(diff, _config())

    assert "No new alerts in this change." in comment
    assert "Existing alerts (1)" in comment


def test_pr_comment_does_not_repeat_an_existing_alert_listed_as_new():
    diff = _comment_diff(new=[_issue("alpha")], existing=[_issue("alpha"), _issue("gamma")])

    comment = Messages.security_comment_template(diff, _config())

    assert "Existing alerts (1)" in comment


def test_pr_comment_stays_within_the_size_budget(monkeypatch):
    monkeypatch.setattr(Messages, "SECURITY_COMMENT_SIZE_BUDGET", 6000)
    diff = _comment_diff(existing=[_issue(f"pkg{i}") for i in range(20)])

    comment = Messages.security_comment_template(diff, _config())

    assert len(comment) < 6500
    assert "more existing alert(s) are not shown" in comment
    assert "Existing alerts (20)" in comment


@pytest.mark.parametrize("budget", [6000, 1])
def test_ignoring_visible_alerts_keeps_the_truncation_warning(monkeypatch, budget):
    monkeypatch.setattr(Messages, "SECURITY_COMMENT_SIZE_BUDGET", budget)
    diff = _comment_diff(existing=[_issue(f"pkg{i}") for i in range(20)])
    body = Messages.security_comment_template(diff, _config())
    visible = re.findall(r"<!-- start-socket-alert-(.*?) -->", body)
    assert len(visible) < len(diff.unchanged_alerts)
    if budget > 1:
        assert visible
    comments = {"ignore": [
        Comment(body_list=[f"@SocketSecurity ignore npm/{package}"])
        for package in visible
    ]}
    assert Comments.remove_alerts(comments, diff.unchanged_alerts)

    updated = Comments.process_security_comment(Comment(body_list=body.splitlines()), comments)

    assert "No dependency alerts to report" not in updated
    assert "more existing alert(s) are not shown" in updated
    assert "[full report](https://socket.dev/diff?action=error%2Cwarn)" in updated
    # Reprocessing the comment must not lose the undisplayed findings either.
    assert Comments.process_security_comment(Comment(body_list=updated.splitlines()), comments) == updated


def test_ignore_all_clears_even_truncated_existing_alerts(monkeypatch):
    monkeypatch.setattr(Messages, "SECURITY_COMMENT_SIZE_BUDGET", 6000)
    diff = _comment_diff(existing=[_issue(f"pkg{i}") for i in range(20)])
    body = Messages.security_comment_template(diff, _config())
    assert "more existing alert(s) are not shown" in body
    comments = {"ignore": [Comment(body_list=["@SocketSecurity ignore-all"])]}

    updated = Comments.process_security_comment(Comment(body_list=body.splitlines()), comments)

    assert "No dependency alerts to report" in updated
    assert "more existing alert(s)" not in updated
    assert "[View full report](https://socket.dev/diff)" in updated


def test_existing_license_violations_use_the_license_row():
    license_alert = _issue("gamma")
    license_alert.type = "licenseSpdxDisj"
    license_alert.title = "License policy violation: GPL-3.0"
    diff = _comment_diff(new=[_issue("alpha")], existing=[license_alert])

    comment = Messages.security_comment_template(diff, _config())
    existing = comment[comment.index("Existing alerts"):]

    assert "gamma@1.0.0 has a License Policy Violation." in existing
    assert "What is known malware?" not in existing
