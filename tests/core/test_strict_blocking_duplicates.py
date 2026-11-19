"""`--strict-blocking` lists each finding once, whatever the baseline.

Added packages must not also count as unchanged. An added package that leaks into
the unchanged set has its alerts reported twice under `--strict-blocking`, once as
new and once as existing, doubling the JSON, SARIF, Slack and GitLab findings and
inflating the "EXISTING blocking issues" count in the summary.

These tests run `Core.create_new_diff` against a mocked diff response, with the
scan upload mocked out, then check what the output layer renders.
"""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from socketdev.fullscans import FullScanParams, StreamDiffResponse

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.alert_selection import select_diff_alerts
from socketsecurity.core.classes import Diff, Issue
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.output import OutputHandler

BUCKETS = ("added", "removed", "unchanged", "replaced", "updated")


@pytest.fixture
def core(mock_sdk_with_responses):
    core = Core(config=SocketConfig(api_key="test_key"), sdk=mock_sdk_with_responses)
    # Force the streaming diff so the mocked response below is the artifact source.
    core.sdk.diffscans.create_from_ids.side_effect = Exception("diff-scans unavailable")
    core.sdk.fullscans.stream_diff.side_effect = None
    return core


def _artifact(diff_type, artifact_id, name, alerts=None, direct=True, ancestors=None):
    ref = {
        "direct": direct,
        "manifestFiles": [{"file": "package.json", "start": 0, "end": 0}] if direct else [],
        "topLevelAncestors": ancestors or [],
    }
    return {
        "diffType": diff_type,
        "type": "npm",
        "name": name,
        "version": "1.0.0",
        "id": artifact_id,
        "head": [] if diff_type in ("removed", "replaced") else [ref],
        "base": [ref] if diff_type in ("removed", "replaced") else [],
        "license": "MIT",
        "licenseDetails": [],
        "author": [],
        "size": 1,
        "score": {},
        "alerts": alerts or [],
    }


def _blocking_alert(key, alert_type="malware"):
    return {
        "key": key,
        "type": alert_type,
        "severity": "critical",
        "category": "supplyChainRisk",
        "props": {},
        "action": "error",
    }


def _diff_response(**buckets):
    raw = json.loads((Path(__file__).parent.parent / "data/fullscans/diff/stream_diff.json").read_text())
    artifacts = {name: buckets.get(name, []) for name in BUCKETS}
    return StreamDiffResponse.from_dict({
        "success": raw["success"],
        "status": raw["status"],
        "data": {**raw["data"], "artifacts": artifacts},
    })


def _build_diff(core, response):
    """Run Core.create_new_diff with the upload mocked out and `response` as the diff."""
    core.sdk.fullscans.stream_diff.return_value = response
    core.resolve_base_full_scan_id = Mock(return_value="head")
    core.create_full_scan = Mock(return_value=SimpleNamespace(id="new"))
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True
    return core.create_new_diff(
        ["/repo"], params, explicit_files=["/repo/package.json"],
    )


def _handler(strict_blocking=True):
    config = Mock(spec=CliConfig)
    config.disable_blocking = False
    config.strict_blocking = strict_blocking
    config.legal_format = "socket"
    config.legal = False
    config.repo = None
    config.branch = None
    config.commit_sha = None
    return OutputHandler(config, Mock())


def test_empty_baseline_lists_added_alerts_once(core):
    """Against an empty baseline every package is added and none is unchanged."""
    diff = _build_diff(core, _diff_response(added=[
        _artifact("added", "a1", "alpha", [_blocking_alert("k1")]),
        _artifact("added", "a2", "beta", [_blocking_alert("k2")]),
    ]))

    assert len(diff.new_alerts) == 2
    assert diff.unchanged_alerts == []

    handler = _handler()
    report = handler.build_json_report(diff)
    assert len(report["new_alerts"]) == 2
    assert not handler.report_pass(diff)

    summary = handler.build_summary_text(diff)
    assert "NEW blocking issues: 2" in summary
    assert "EXISTING blocking issues" not in summary


def test_real_baseline_lists_new_and_existing_alerts_once_each(core):
    """With a baseline, added alerts are new and unchanged alerts are existing."""
    diff = _build_diff(core, _diff_response(
        added=[_artifact("added", "a1", "alpha", [_blocking_alert("k1")])],
        unchanged=[_artifact("unchanged", "u1", "gamma", [_blocking_alert("k3")])],
    ))

    assert [a.pkg_name for a in diff.new_alerts] == ["alpha"]
    assert [a.pkg_name for a in diff.unchanged_alerts] == ["gamma"]

    handler = _handler()
    report = handler.build_json_report(diff)
    assert sorted(a["pkg_name"] for a in report["new_alerts"]) == ["alpha", "gamma"]
    assert not handler.report_pass(diff)

    summary = handler.build_summary_text(diff)
    assert "NEW blocking issues: 1" in summary
    assert "EXISTING blocking issues: 1" in summary


def test_real_baseline_fails_on_existing_alerts_alone(core):
    """An unchanged blocking alert fails the run when the API returns it."""
    diff = _build_diff(core, _diff_response(
        unchanged=[_artifact("unchanged", "u1", "gamma", [_blocking_alert("k3")])],
    ))

    assert diff.new_alerts == []
    assert not _handler(strict_blocking=True).report_pass(diff)
    assert _handler(strict_blocking=False).report_pass(diff)


def test_without_strict_blocking_output_is_unchanged(core):
    diff = _build_diff(core, _diff_response(
        added=[_artifact("added", "a1", "alpha", [_blocking_alert("k1")])],
        unchanged=[_artifact("unchanged", "u1", "gamma", [_blocking_alert("k3")])],
    ))

    report = _handler(strict_blocking=False).build_json_report(diff)
    assert [a["pkg_name"] for a in report["new_alerts"]] == ["alpha"]


def test_unchanged_packages_are_keyed_by_artifact_id(core):
    """Transitive unchanged alerts resolve their introducer through the ancestor ID."""
    diff = _build_diff(core, _diff_response(unchanged=[
        _artifact("unchanged", "top", "parent"),
        _artifact(
            "unchanged", "dep", "child", [_blocking_alert("k5")],
            direct=False, ancestors=["top"],
        ),
    ]))

    assert diff.unchanged_alerts[0].introduced_by == [("npm/parent@1.0.0", "package.json")]


def _issue(name, alert_type="malware", pkg_type="npm"):
    return Issue(
        pkg_type=pkg_type,
        pkg_name=name,
        pkg_version="1.0.0",
        type=alert_type,
        purl=f"{name}@1.0.0",
        error=True,
    )


def test_select_diff_alerts_skips_unchanged_alert_already_listed_as_new():
    diff = Diff()
    diff.new_alerts = [_issue("alpha")]
    diff.unchanged_alerts = [_issue("alpha"), _issue("alpha", "typosquat"), _issue("gamma")]

    selected = select_diff_alerts(diff, strict_blocking=True)

    assert [(a.pkg_name, a.type) for a in selected] == [
        ("alpha", "malware"),
        ("alpha", "typosquat"),
        ("gamma", "malware"),
    ]


def test_select_diff_alerts_keeps_same_purl_from_another_ecosystem():
    """`Issue.purl` has no ecosystem, so npm and PyPI packages can share one."""
    diff = Diff()
    diff.new_alerts = [_issue("alpha", pkg_type="npm")]
    diff.unchanged_alerts = [_issue("alpha", pkg_type="pypi")]

    selected = select_diff_alerts(diff, strict_blocking=True)

    assert [a.pkg_type for a in selected] == ["npm", "pypi"]
