"""The full scan supplies current alerts omitted by the comparison."""
import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from socketdev.exceptions import APIFailure
from socketdev.fullscans import (
    FullScanParams,
    FullScans,
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


def _diff_artifact(diff_type, artifact_id, name, alerts=None, *, version="1.0.0"):
    ref = {
        "direct": True,
        "manifestFiles": [{"file": "package.json", "start": 0, "end": 0}],
        "topLevelAncestors": [],
    }
    return {
        "diffType": diff_type,
        "type": "npm",
        "name": name,
        "version": version,
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


def _scan_artifact(artifact_id, name, alerts, *, version="1.0.0"):
    return {
        "type": "npm",
        "name": name,
        "version": version,
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


def _run(core, *flags, scan_alerts=None, scan_id="u1"):
    core.cli_config = CliConfig.from_args(["--api-token", "test", *flags])
    core.sdk.fullscans.stream_diff.return_value = _diff_response(
        added=[_diff_artifact("added", "a1", "alpha", [_alert("k1")])],
        unchanged=[_diff_artifact("unchanged", "u1", "gamma")],
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


@pytest.mark.parametrize("change_type", ["added", "updated"])
@pytest.mark.parametrize("strict", [True, False])
def test_blocking_cve_persists_across_a_version_change(core, change_type, strict):
    flags = ["--strict-blocking"] if strict else []
    core.cli_config = CliConfig.from_args(["--api-token", "test", *flags])
    alert = {**_alert("persistent", alert_type="criticalCVE"), "props": {"cveId": "CVE-2025-12345"}}
    core.sdk.diffscans.create_from_ids.side_effect = None
    core.sdk.diffscans.create_from_ids.return_value = {"diff_scan": {"id": "comparison"}}
    artifacts = {key: [] for key in ("added", "removed", "unchanged", "replaced", "updated")}
    artifacts[change_type] = [_diff_artifact(change_type, "a2", "alpha", version="2.0.0")]
    artifacts["replaced"] = [_diff_artifact("replaced", "a1", "alpha", [alert])]
    core.sdk.diffscans.get.return_value = {"diff_scan": {"artifacts": artifacts}}
    _stream_through_sdk(
        core,
        _scan_artifact("a2", "alpha", [alert], version="2.0.0"),
    )
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    diff = core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])

    assert diff.new_alerts == []
    assert _handler(strict_blocking=strict).report_pass(diff) is (not strict)
    if strict:
        assert [(a.purl, a.advisory_id()) for a in diff.unchanged_alerts] == [
            ("alpha@2.0.0", "CVE-2025-12345"),
        ]
        comment = Messages.security_comment_template(diff, _config())
        existing_table = comment.split("<!-- start-socket-existing-alerts -->")[1]
        assert "alpha@2.0.0" in existing_table
        assert "CVE-2025-12345" in existing_table
        core.sdk.fullscans.stream.assert_called_once_with(core.config.org_slug, "new", use_types=True)
    else:
        assert diff.unchanged_alerts == []
        core.sdk.fullscans.stream.assert_not_called()


def test_strict_blocking_loads_unchanged_and_updated_alerts_once(core):
    core.cli_config = CliConfig.from_args(["--api-token", "test", "--strict-blocking"])
    new_alert = {**_alert("new", alert_type="criticalCVE"), "props": {"cveId": "CVE-2025-12345"}}
    existing_alert = {**_alert("existing", alert_type="criticalCVE"), "props": {"cveId": "CVE-2025-54321"}}
    updated = _diff_artifact("updated", "a2", "alpha", [new_alert], version="2.0.0")
    replaced = _diff_artifact("replaced", "a1", "alpha", [
        {**existing_alert, "action": "warn"}, _alert("resolved"),
    ])
    updated["namespace"] = replaced["namespace"] = "@team"
    core.sdk.fullscans.stream_diff.return_value = _diff_response(
        updated=[updated],
        replaced=[replaced],
        unchanged=[_diff_artifact("unchanged", "u1", "gamma")],
    )
    scanned = _scan_artifact("head-a2", "alpha", [new_alert, existing_alert], version="2.0.0")
    scanned["namespace"] = "@team"
    core.sdk.fullscans.stream.return_value = _scan_response(
        scanned,
        _scan_artifact("u1", "gamma", [_alert("unchanged")]),
    )
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    diff = core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])

    assert [a.key for a in diff.new_alerts] == ["new"]
    assert {(a.purl, a.key, a.error) for a in diff.unchanged_alerts} == {
        ("@team/alpha@2.0.0", "existing", True),
        ("gamma@1.0.0", "unchanged", True),
    }
    core.sdk.fullscans.stream.assert_called_once()


@pytest.mark.parametrize("reported_as_new", [True, False])
def test_block_action_takes_precedence_over_warning_for_the_same_advisory(core, reported_as_new):
    core.cli_config = CliConfig.from_args(["--api-token", "test", "--strict-blocking"])
    warning = _cve_alert("GHSA-w457-6q6x-cgp9", "CVE-2019-19919", action="warn")
    blocking = {**warning, "action": "error", "key": "block", "file": "repo/second/package.json"}
    core.sdk.fullscans.stream_diff.return_value = _diff_response(
        updated=[_diff_artifact("updated", "a2", "alpha", [warning] if reported_as_new else [], version="2.0.0")],
        replaced=[_diff_artifact("replaced", "a1", "alpha", [] if reported_as_new else [blocking])],
    )
    scan_alerts = [blocking] if reported_as_new else [{**warning, "file": "repo/first/package.json"}, blocking]
    _stream_through_sdk(core, _scan_artifact("a2", "alpha", scan_alerts, version="2.0.0"))
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    diff = core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])

    assert len(diff.new_alerts) == int(reported_as_new)
    assert len(diff.unchanged_alerts) == int(not reported_as_new)
    assert (diff.new_alerts or diff.unchanged_alerts)[0].error
    assert not _handler().report_pass(diff)


def test_existing_transitive_alert_includes_its_unchanged_ancestor_in_the_pr_comment(core):
    core.cli_config = CliConfig.from_args(["--api-token", "test", "--strict-blocking"])
    updated = _diff_artifact("updated", "child2", "child", version="2.0.0")
    updated["head"] = [{"direct": False, "manifestFiles": [], "topLevelAncestors": ["parent"]}]
    parent = _diff_artifact("unchanged", "parent", "parent")
    parent["namespace"] = "@team"
    alert = _alert("persistent")
    core.sdk.fullscans.stream_diff.return_value = _diff_response(
        updated=[updated],
        replaced=[_diff_artifact("replaced", "child1", "child", [alert])],
        unchanged=[parent],
    )
    _stream_through_sdk(
        core,
        _scan_artifact("child2", "child", [alert], version="2.0.0"),
        {**_scan_artifact("parent", "parent", []), "namespace": "@team"},
    )
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    diff = core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])

    ancestor = "npm/@team/parent@1.0.0"
    assert diff.unchanged_alerts[0].introduced_by == [(ancestor, "package.json")]
    comment = Messages.security_comment_template(diff, _config())
    existing_table = comment.split("<!-- start-socket-existing-alerts -->")[1]
    assert f"<strong>Introduced by:</strong> <code>{ancestor}</code>" in existing_table


def test_strict_blocking_skips_full_scan_fetch_for_a_new_dependency(core):
    core.cli_config = CliConfig.from_args(["--api-token", "test", "--strict-blocking"])
    core.sdk.fullscans.stream_diff.return_value = _diff_response(
        added=[_diff_artifact("added", "a1", "alpha", [_alert("introduced")])],
        removed=[_diff_artifact("removed", "b1", "beta")],
    )
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    diff = core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])

    core.sdk.fullscans.stream.assert_not_called()
    assert [alert.key for alert in diff.new_alerts] == ["introduced"]
    assert diff.unchanged_alerts == []


def test_strict_blocking_fails_if_changed_package_is_missing_from_full_scan(core):
    core.cli_config = CliConfig.from_args(["--api-token", "test", "--strict-blocking"])
    core.sdk.fullscans.stream_diff.return_value = _diff_response(
        updated=[_diff_artifact("updated", "a2", "alpha", version="2.0.0")],
    )
    core.sdk.fullscans.stream.return_value = _scan_response(
        _scan_artifact("a1", "alpha", []),
    )
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    with pytest.raises(InfrastructureError, match="current packages.*full scan new"):
        core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])


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
    """An unchanged-only comparison can already have all the alerts it needs."""
    core.cli_config = CliConfig.from_args(["--api-token", "test", "--strict-blocking"])
    core.sdk.fullscans.stream_diff.return_value = _diff_response(
        unchanged=[_diff_artifact("unchanged", "u1", "gamma", [_alert("k3")])],
    )
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    diff = core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])

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


HANDLEBARS_CRITICAL_ADVISORIES = [
    ("GHSA-8r5x-fm3f-whwj", ""),
    ("GHSA-p8wg-vrv2-v86f", ""),
    ("GHSA-2w6w-674q-4c4q", ""),
    ("GHSA-w457-6q6x-cgp9", "CVE-2019-19919"),
    ("GHSA-765h-qjxv-5f44", "CVE-2021-23383"),
    ("GHSA-f2jv-r9rf-7988", "CVE-2021-23369"),
]


def _cve_alert(ghsa_id, cve_id, action="error"):
    return {
        "key": f"key-{ghsa_id}",
        "type": "criticalCVE",
        "severity": "critical",
        "category": "vulnerability",
        "props": {"ghsaId": ghsa_id, "cveId": cve_id, "title": f"Advisory {ghsa_id}"},
        "action": action,
    }


def _stream_through_sdk(core, *artifacts):
    """Serve ``artifacts`` as the full-scan NDJSON body and parse it with the real SDK."""
    response = Mock(status_code=200, text="\n".join(json.dumps(a) for a in artifacts))
    api = Mock(request_timeout=30)
    api.do_request.return_value = response
    core.sdk.fullscans.stream.side_effect = FullScans(api).stream


def _existing_only_diff(core, *scan_artifacts):
    core.cli_config = CliConfig.from_args(["--api-token", "test", "--strict-blocking"])
    core.sdk.fullscans.stream_diff.return_value = _diff_response(unchanged=[
        _diff_artifact("unchanged", artifact["id"], artifact["name"]) for artifact in scan_artifacts
    ])
    _stream_through_sdk(core, *scan_artifacts)
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True
    return core.create_new_diff(["/repo"], params, explicit_files=["/repo/package.json"])


def test_every_same_severity_advisory_on_an_unchanged_package_is_kept(core, caplog):
    alerts = [_cve_alert(ghsa, cve) for ghsa, cve in HANDLEBARS_CRITICAL_ADVISORIES]

    with caplog.at_level("INFO"):
        diff = _existing_only_diff(core, _scan_artifact("u1", "handlebars", alerts))

    assert sorted(a.advisory_id() for a in diff.unchanged_alerts) == sorted(
        ghsa.upper() for ghsa, _ in HANDLEBARS_CRITICAL_ADVISORIES
    )
    assert all(a.error for a in diff.unchanged_alerts)
    assert "Loaded 6 alerts for 1 of 1 unchanged packages" in caplog.text
    assert not _handler(strict_blocking=True).report_pass(diff)

    comment = Messages.security_comment_template(diff, _config())
    assert "Existing alerts (6)" in comment
    for ghsa, _ in HANDLEBARS_CRITICAL_ADVISORIES:
        assert ghsa.upper() in comment


@pytest.mark.parametrize("triaged_action", ["ignore", "monitor"])
def test_a_triaged_advisory_does_not_hide_a_blocking_one_on_the_same_package(core, triaged_action):
    """The triaged advisory comes first in the stream; the Block one must still fail the run."""
    alerts = [
        _cve_alert("GHSA-w457-6q6x-cgp9", "CVE-2019-19919", action=triaged_action),
        _cve_alert("GHSA-765h-qjxv-5f44", "CVE-2021-23383", action="error"),
    ]

    diff = _existing_only_diff(core, _scan_artifact("u1", "handlebars", alerts))

    assert [(a.advisory_id(), a.error) for a in diff.unchanged_alerts] == [("GHSA-765H-QJXV-5F44", True)]
    assert not _handler(strict_blocking=True).report_pass(diff)


@pytest.mark.parametrize("direct", [True, False])
def test_full_scan_reports_distinguish_advisories_on_the_same_manifest(core, direct):
    core.cli_config = CliConfig.from_args([
        "--api-token", "test", "--enable-json", "--enable-sarif", "--enable-gitlab-security",
    ])
    advisories = HANDLEBARS_CRITICAL_ADVISORIES[:2]
    alerts = [_cve_alert(ghsa, cve) for ghsa, cve in advisories]
    artifact = _scan_artifact("u1", "handlebars", alerts)
    artifact["direct"] = direct
    _stream_through_sdk(core, artifact)
    params = FullScanParams(repo="repo", branch="feature")

    diff = core.create_full_scan_with_report_url(["/repo"], params, explicit_files=["/repo/package.json"])

    expected_ids = {ghsa.upper() for ghsa, _ in advisories}
    report = OutputHandler(core.cli_config, core.sdk).build_json_report(diff)
    assert {alert["props"]["ghsaId"].upper() for alert in report["new_alerts"]} == expected_ids
    sarif = Messages.create_security_comment_sarif(diff)["runs"][0]
    assert len(sarif["tool"]["driver"]["rules"]) == 2
    assert len(sarif["results"]) == 2
    assert {result["ruleId"].split()[1] for result in sarif["results"]} == expected_ids
    assert {result["message"]["text"].split("<br/>")[0] for result in sarif["results"]} == expected_ids
    assert {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in sarif["results"]
    } == {"package.json"}
    gitlab = Messages.create_security_comment_gitlab(diff)
    assert len({finding["id"] for finding in gitlab["vulnerabilities"]}) == 2


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

    assert len(comment.encode()) <= Messages.SECURITY_COMMENT_SIZE_BUDGET
    assert "more existing alert(s) are not shown" in comment
    assert "Existing alerts (20)" in comment


def test_existing_comment_truncation_keeps_the_blocking_first_order(monkeypatch):
    monkeypatch.setattr(Messages, "SECURITY_COMMENT_SIZE_BUDGET", 6000)
    large_blocker = _issue("large-blocker")
    large_blocker.description = "é" * 3000
    diff = _comment_diff(existing=[
        _issue("later-warning", error=False, warn=True),
        _issue("first-blocker"),
        large_blocker,
    ])

    comment = Messages.security_comment_template(diff, _config())

    assert "first-blocker@1.0.0" in comment
    assert "large-blocker@1.0.0" not in comment
    assert "later-warning@1.0.0" not in comment
    assert "2 more existing alert(s) are not shown" in comment
    assert "[View full report](https://socket.dev/diff?action=error%2Cwarn)" in comment


def test_omitted_existing_blocker_still_fails_strict_blocking(monkeypatch):
    monkeypatch.setattr(Messages, "SECURITY_COMMENT_SIZE_BUDGET", 6000)
    new = [_issue(f"new-{index}", error=False, warn=True) for index in range(20)]
    diff = _comment_diff(new=new, existing=[_issue("existing-blocker")])
    diff.unchanged_alerts[0].description = "é" * 3000

    comment = Messages.security_comment_template(diff, _config())

    assert Messages.EXISTING_ALERTS_TRUNCATED_MARKER in comment
    assert "existing-blocker@1.0.0" not in comment
    assert _handler().return_exit_code(diff) == 1
    assert _handler(strict_blocking=False).return_exit_code(diff) == 0


@pytest.mark.parametrize("budget", [6000, 1500])
def test_ignoring_visible_alerts_keeps_the_truncation_warning(monkeypatch, budget):
    monkeypatch.setattr(Messages, "SECURITY_COMMENT_SIZE_BUDGET", budget)
    diff = _comment_diff(existing=[_issue(f"pkg{i}") for i in range(20)])
    body = Messages.security_comment_template(diff, _config())
    visible = re.findall(r"<!-- start-socket-alert-(.*?) -->", body)
    assert len(visible) < len(diff.unchanged_alerts)
    assert bool(visible) == (budget == 6000)
    comments = {"ignore": [
        Comment(body_list=[f"@SocketSecurity ignore npm/{package}"])
        for package in visible
    ]}
    assert Comments.remove_alerts(comments, diff.unchanged_alerts)

    updated = Comments.process_security_comment(Comment(body_list=body.splitlines()), comments)

    assert "No dependency alerts to report" not in updated
    assert "more existing alert(s) are not shown" in updated
    assert "[View full report](https://socket.dev/diff?action=error%2Cwarn)" in updated
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
