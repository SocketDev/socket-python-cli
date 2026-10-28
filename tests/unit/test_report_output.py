import copy
import json

from socketsecurity.config import CliConfig
from socketsecurity.core.classes import Diff, Issue
from socketsecurity.core.report_output import (
    build_console_summary,
    build_report_references,
    build_socket_json_report,
)


def _config(*, strict_blocking: bool = False) -> CliConfig:
    return CliConfig(
        api_token="",
        repo="fictional-repo",
        strict_blocking=strict_blocking,
    )


def _issue(
    title: str,
    *,
    error: bool = False,
    warn: bool = False,
) -> Issue:
    return Issue(
        pkg_type="pypi",
        pkg_name="fictional-package",
        pkg_version="1.2.3",
        category="supply-chain",
        type=title,
        severity="high" if error else "medium",
        pkg_id="pypi/fictional-package@1.2.3",
        props={},
        key=title,
        error=error,
        warn=warn,
        ignore=False,
        monitor=False,
        description=f"Description for {title}",
        title=title,
        emoji="!",
        next_step_title="Review the package",
        suggestion="Use a safe version",
        introduced_by=[("fictional-root", "requirements.txt")],
        manifests="requirements.txt",
        url="https://socket.dev/pypi/package/fictional-package/alerts/1.2.3",
        purl="pkg:pypi/fictional-package@1.2.3",
    )


def _diff(
    *,
    new_alerts: list[Issue] | None = None,
    unchanged_alerts: list[Issue] | None = None,
    report_url: str | None = "https://socket.dev/orgs/fictional/reports/full-123",
    diff_url: str | None = "https://socket.dev/orgs/fictional/diffs/diff-456",
    is_full_scan: bool = False,
    alerts_fetched: bool = True,
) -> Diff:
    return Diff(
        id="full-123",
        new_scan_id="full-123",
        report_url=report_url,
        diff_url=diff_url,
        is_full_scan=is_full_scan,
        alerts_fetched=alerts_fetched,
        new_alerts=list(new_alerts or []),
        unchanged_alerts=list(unchanged_alerts or []),
    )


def test_comparison_prefers_diff_url_and_json_preserves_both_references():
    diff = _diff(
        new_alerts=[_issue("New warning", warn=True)],
        report_url="https://reports.example.test/full?scan=one",
        diff_url="https://compare.example.test/pairs/a%2Fb?view=full",
    )
    original = copy.deepcopy(diff.__dict__)

    summary = build_console_summary(diff, _config())
    report = build_socket_json_report(diff, _config())

    assert "Diff Url: https://compare.example.test/pairs/a%2Fb?view=full" in summary
    assert "Report Url:" not in summary
    assert report["full_scan_id"] == "full-123"
    assert report["diff_url"] == "https://compare.example.test/pairs/a%2Fb?view=full"
    assert report["report_url"] == "https://reports.example.test/full?scan=one"
    assert diff.__dict__ == original


def test_clean_comparison_keeps_message_first_and_includes_diff_link():
    diff = _diff(new_alerts=[])

    summary = build_console_summary(diff, _config())
    report = build_socket_json_report(diff, _config())

    assert summary.splitlines()[0] == "No issues found"
    assert "Diff Url: https://socket.dev/orgs/fictional/diffs/diff-456" in summary
    assert report["new_alerts"] == []
    assert report["scan_failed"] is False


def test_warning_and_blocking_summary_counts_and_json_failure_are_preserved():
    diff = _diff(
        new_alerts=[
            _issue("Blocking alert", error=True),
            _issue("Warning alert", warn=True),
        ]
    )

    summary = build_console_summary(diff, _config())
    report = build_socket_json_report(diff, _config())
    decoded_alerts = [json.loads(json.dumps(alert)) for alert in report["new_alerts"]]

    assert "NEW blocking issues: 1" in summary
    assert "NEW warning issues: 1" in summary
    assert "Blocking alert" in summary
    assert "Warning alert" in summary
    assert report["scan_failed"] is True
    assert [alert["title"] for alert in decoded_alerts] == [
        "Blocking alert",
        "Warning alert",
    ]


def test_strict_blocking_adds_unchanged_alerts_without_changing_references():
    unchanged = _issue("Existing blocking alert", error=True)
    diff = _diff(new_alerts=[], unchanged_alerts=[unchanged])

    ordinary = build_console_summary(diff, _config())
    strict = build_console_summary(diff, _config(strict_blocking=True))
    ordinary_json = build_socket_json_report(diff, _config())
    strict_json = build_socket_json_report(diff, _config(strict_blocking=True))

    assert "Existing blocking alert" not in ordinary
    assert "Existing blocking alert" in strict
    assert ordinary_json["new_alerts"] == []
    assert [alert["title"] for alert in strict_json["new_alerts"]] == [
        "Existing blocking alert"
    ]
    assert ordinary_json["diff_url"] == strict_json["diff_url"]
    assert ordinary_json["report_url"] == strict_json["report_url"]


def test_full_scan_uses_report_url_and_non_new_finding_labels():
    diff = _diff(
        new_alerts=[_issue("Full scan warning", warn=True)],
        is_full_scan=True,
    )

    summary = build_console_summary(diff, _config())

    assert "Blocking issues:" not in summary
    assert "Warning issues: 1" in summary
    assert "NEW warning issues" not in summary
    assert "whole repository, with no baseline" in summary
    assert "Report Url: https://socket.dev/orgs/fictional/reports/full-123" in summary
    assert "Diff Url:" not in summary


def test_clean_full_scan_uses_diff_url_as_report_url_fallback():
    diff = _diff(
        new_alerts=[],
        report_url="",
        diff_url="https://reports.example.test/full-scan-fallback",
        is_full_scan=True,
    )

    summary = build_console_summary(diff, _config())

    assert summary.splitlines()[0] == "No issues found"
    assert "Report Url: https://reports.example.test/full-scan-fallback" in summary
    assert "Diff Url:" not in summary


def test_full_scan_without_fetched_findings_retains_explicit_state_and_report_link():
    diff = _diff(is_full_scan=True, alerts_fetched=False)

    summary = build_console_summary(diff, _config())

    assert summary.startswith(
        "Full scan completed. Findings were not fetched for console output."
    )
    assert "No issues found" not in summary
    assert "Report Url: https://socket.dev/orgs/fictional/reports/full-123" in summary


def test_comparison_report_url_fallback_and_missing_links():
    with_report = _diff(
        new_alerts=[_issue("Warning", warn=True)],
        diff_url="",
        report_url="https://reports.example.test/alternate",
    )
    without_urls = _diff(
        new_alerts=[_issue("Warning", warn=True)],
        diff_url="",
        report_url="",
    )

    report_fallback_summary = build_console_summary(with_report, _config())
    no_link_summary = build_console_summary(without_urls, _config())

    assert (
        "Report Url: https://reports.example.test/alternate" in report_fallback_summary
    )
    assert "Diff Url:" not in report_fallback_summary
    assert "Report Url:" not in no_link_summary
    assert "Diff Url:" not in no_link_summary
    assert "None" not in no_link_summary
    assert "undefined" not in no_link_summary


def test_console_link_preserves_alternate_server_url_exactly():
    custom_url = "https://reports.example.test:9443/tenant/a%2Fb?view=x%2Fy&lang=en"
    diff = _diff(report_url=custom_url, diff_url="")

    summary = build_console_summary(diff, _config())
    references = build_report_references(diff)

    assert summary.endswith(f"Report Url: {custom_url}")
    assert references.console_link() == ("Report Url", custom_url)


def test_default_socket_json_key_set_and_metadata_remain_unchanged():
    diff = _diff(new_alerts=[])
    config = CliConfig(
        api_token="",
        repo="fictional-repo",
        branch="feature/example",
        commit_sha="abc123",
        legal=True,
    )

    report = build_socket_json_report(diff, config)

    assert set(report) == {
        "scan_failed",
        "new_alerts",
        "full_scan_id",
        "diff_url",
        "report_url",
        "repo",
        "branch",
        "commit_sha",
        "legal_mode",
    }
    assert report == {
        "scan_failed": False,
        "new_alerts": [],
        "full_scan_id": "full-123",
        "diff_url": "https://socket.dev/orgs/fictional/diffs/diff-456",
        "report_url": "https://socket.dev/orgs/fictional/reports/full-123",
        "repo": "fictional-repo",
        "branch": "feature/example",
        "commit_sha": "abc123",
        "legal_mode": True,
    }


def test_missing_reference_fields_keep_existing_json_defaults():
    diff = Diff(new_alerts=[])

    summary = build_console_summary(diff, _config())
    report = build_socket_json_report(diff, _config())

    assert summary == "No issues found"
    assert report["full_scan_id"] == ""
    assert report["diff_url"] == ""
    assert report["report_url"] is None
