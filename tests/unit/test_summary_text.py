"""How the console summary distinguishes a comparison from a full scan.

A full scan carries every finding in the repository, not the ones a change
introduced, and blocking is suppressed for exactly that reason. The summary has
to say so, or the reported counts read as gating failures that returned 0.
"""
from unittest.mock import MagicMock

from socketsecurity.config import CliConfig
from socketsecurity.core.classes import Diff, Issue
from socketsecurity.output import OutputHandler


def _issue(name: str, error: bool = False, warn: bool = False) -> Issue:
    return Issue(
        pkg_name=name,
        pkg_version="1.0.0",
        severity="high",
        title=f"Vuln in {name}",
        description="test",
        type="vulnerability",
        manifests="pom.xml",
        pkg_type="maven",
        key=f"key-{name}",
        purl=f"pkg:maven/{name}@1.0.0",
        url=f"https://socket.dev/maven/package/{name}/overview/1.0.0",
        error=error,
        warn=warn,
    )


def _handler() -> OutputHandler:
    return OutputHandler(CliConfig.from_args(["--api-token", "test"]), MagicMock())


def _diff(is_full_scan: bool) -> Diff:
    diff = Diff()
    diff.new_alerts = [_issue("alpha", error=True), _issue("beta", warn=True)]
    diff.id = "scan-id"
    diff.report_url = "https://socket.dev/dashboard/org/test/sbom/scan-id"
    diff.diff_url = diff.report_url
    diff.is_full_scan = is_full_scan
    diff.alerts_fetched = is_full_scan
    return diff


def test_comparison_reports_findings_as_new():
    summary = _handler().build_summary_text(_diff(is_full_scan=False))

    assert "NEW blocking issues: 1" in summary
    assert "NEW warning issues: 1" in summary
    assert "Diff Url:" in summary


def test_full_scan_does_not_report_findings_as_new():
    summary = _handler().build_summary_text(_diff(is_full_scan=True))

    assert "NEW" not in summary
    assert "Blocking issues: 1" in summary
    assert "Warning issues: 1" in summary


def test_full_scan_labels_its_link_as_a_report():
    summary = _handler().build_summary_text(_diff(is_full_scan=True))

    assert "Report Url:" in summary
    assert "Diff Url:" not in summary


def test_full_scan_explains_why_the_counts_do_not_gate():
    summary = _handler().build_summary_text(_diff(is_full_scan=True))

    assert "no baseline to compare against" in summary
    assert "do not affect the exit code" in summary
