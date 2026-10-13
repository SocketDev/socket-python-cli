import copy
import json

from socketsecurity.config import CliConfig
from socketsecurity.core.classes import Diff, Issue, Package, Purl
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


def _purl(
    package_id: str,
    name: str,
    version: str,
    ecosystem: str,
    *,
    namespace: str = "",
    scores: dict[str, int | float | None] | None = None,
    direct: bool = True,
    introduced_by: list[tuple[str, str]] | None = None,
    capabilities: list[str] | None = None,
    is_new: bool = False,
) -> Purl:
    package_path = f"{namespace}/{name}" if namespace else name
    return Purl(
        id=package_id,
        name=name,
        version=version,
        ecosystem=ecosystem,
        direct=direct,
        author=["Fictional Maintainer"],
        size=23,
        transitives=4,
        introduced_by=introduced_by or [("fictional-root", "requirements.txt")],
        capabilities=capabilities or [],
        is_new=is_new,
        url=f"https://socket.dev/{ecosystem}/package/{package_path}/overview/{version}",
        purl=f"{package_path}@{version}",
        scores=scores,
    )


def _diff(
    *,
    new_alerts: list[Issue] | None = None,
    unchanged_alerts: list[Issue] | None = None,
    report_url: str | None = "https://socket.dev/orgs/fictional/reports/full-123",
    diff_url: str | None = "https://socket.dev/orgs/fictional/diffs/diff-456",
    is_full_scan: bool = False,
    alerts_fetched: bool = True,
    diff_scan_id: str | None = None,
    old_scan_id: str | None = None,
    new_scan_id: str | None = "full-123",
    old_scan_url: str | None = None,
    new_scan_url: str | None = None,
) -> Diff:
    return Diff(
        id="full-123",
        report_url=report_url,
        diff_url=diff_url,
        is_full_scan=is_full_scan,
        alerts_fetched=alerts_fetched,
        diff_scan_id=diff_scan_id,
        old_scan_id=old_scan_id,
        new_scan_id=new_scan_id,
        old_scan_url=old_scan_url,
        new_scan_url=new_scan_url,
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
        "diff_scan_id",
        "old_scan_id",
        "new_scan_id",
        "old_scan_url",
        "new_scan_url",
        "new_packages",
        "updated_packages",
        "removed_packages",
        "replaced_packages",
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
        "diff_scan_id": None,
        "old_scan_id": None,
        "new_scan_id": "full-123",
        "old_scan_url": None,
        "new_scan_url": None,
        "new_packages": [],
        "updated_packages": [],
        "removed_packages": [],
        "replaced_packages": [],
    }


def test_scan_references_are_distinct_nullable_and_preserve_input():
    diff = _diff(
        diff_scan_id="comparison-789",
        old_scan_id="baseline-456",
        new_scan_id="full-123",
        old_scan_url="https://reports.example.test/before?x=1#base",
        new_scan_url="https://reports.example.test/after?x=2#new",
    )
    original = copy.deepcopy(diff.__dict__)

    report = build_socket_json_report(diff, _config())

    assert report == {
        "scan_failed": False,
        "new_alerts": [],
        "full_scan_id": "full-123",
        "diff_url": "https://socket.dev/orgs/fictional/diffs/diff-456",
        "report_url": "https://socket.dev/orgs/fictional/reports/full-123",
        "repo": "fictional-repo",
        "branch": "",
        "commit_sha": "",
        "legal_mode": False,
        "diff_scan_id": "comparison-789",
        "old_scan_id": "baseline-456",
        "new_scan_id": "full-123",
        "old_scan_url": "https://reports.example.test/before?x=1#base",
        "new_scan_url": "https://reports.example.test/after?x=2#new",
        "new_packages": [],
        "updated_packages": [],
        "removed_packages": [],
        "replaced_packages": [],
    }
    assert json.loads(json.dumps(report))["old_scan_id"] == "baseline-456"
    for field, value in original.items():
        if field in {
            "new_packages",
            "updated_packages",
            "removed_packages",
            "replaced_packages",
        }:
            assert [package.__dict__ for package in getattr(diff, field)] == [
                package.__dict__ for package in value
            ]
        else:
            assert getattr(diff, field) == value


def test_missing_references_remain_null_without_url_inference():
    diff = _diff(
        report_url="https://reports.example.test/display",
        diff_url=None,
        diff_scan_id=None,
        old_scan_id=None,
        new_scan_id=None,
        old_scan_url=None,
        new_scan_url=None,
    )

    report = build_socket_json_report(diff, _config())

    assert report["diff_scan_id"] is None
    assert report["new_scan_id"] is None
    assert report["new_scan_url"] is None
    assert report["diff_url"] is None
    assert report["report_url"] == "https://reports.example.test/display"


def test_canonical_scan_url_is_distinct_from_display_report_url():
    canonical_url = "https://reports.example.test/scan?id=full-123#result"
    display_url = "https://reports.example.test/scan?id=full-123&include_license_details=false#result"
    diff = _diff(report_url=display_url, new_scan_url=canonical_url)

    report = build_socket_json_report(diff, _config())

    assert report["new_scan_url"] == canonical_url
    assert report["report_url"] == display_url


def test_missing_reference_fields_keep_existing_json_defaults():
    diff = Diff(new_alerts=[])

    summary = build_console_summary(diff, _config())
    report = build_socket_json_report(diff, _config())

    assert summary == "No issues found"
    assert report["full_scan_id"] == ""
    assert report["diff_url"] == ""
    assert report["report_url"] is None
    assert report["new_packages"] == []
    assert report["updated_packages"] == []
    assert report["removed_packages"] == []
    assert report["replaced_packages"] == []


def test_package_change_lists_preserve_exact_public_fields_and_scores():
    added = _purl(
        "added-id",
        "added-package",
        "1.0.0",
        "npm",
        scores={"supplyChain": 0, "quality": 0.25, "license": None},
        capabilities=["network"],
        is_new=True,
    )
    updated = _purl(
        "updated-id",
        "changed-package",
        "2.0.0",
        "pypi",
        scores={"overall": 1, "maintenance": 0.5},
    )
    removed = _purl(
        "removed-id",
        "removed-package",
        "3.0.0",
        "cargo",
        scores={"vulnerability": 0, "quality": 1, "overall": None},
    )
    replaced = _purl(
        "replaced-id",
        "changed-package",
        "1.0.0",
        "pypi",
        scores={"license": 0.75},
    )
    diff = _diff()
    diff.new_packages = [added]
    diff.updated_packages = [updated]
    diff.removed_packages = [removed]
    diff.replaced_packages = [replaced]
    original = copy.deepcopy(diff.__dict__)

    report = build_socket_json_report(diff, _config())

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
        "diff_scan_id",
        "old_scan_id",
        "new_scan_id",
        "old_scan_url",
        "new_scan_url",
        "new_packages",
        "updated_packages",
        "removed_packages",
        "replaced_packages",
    }
    expected_row_keys = {
        "id",
        "name",
        "version",
        "ecosystem",
        "direct",
        "author",
        "size",
        "transitives",
        "introduced_by",
        "capabilities",
        "is_new",
        "author_url",
        "url",
        "purl",
        "scores",
    }
    expected = {
        "new_packages": {
            "id": "added-id",
            "name": "added-package",
            "version": "1.0.0",
            "ecosystem": "npm",
            "direct": True,
            "author": ["Fictional Maintainer"],
            "size": 23,
            "transitives": 4,
            "introduced_by": [("fictional-root", "requirements.txt")],
            "capabilities": ["network"],
            "is_new": True,
            "author_url": "[Fictional Maintainer](https://socket.dev/npm/user/Fictional Maintainer)",
            "url": "https://socket.dev/npm/package/added-package/overview/1.0.0",
            "purl": "added-package@1.0.0",
            "scores": {"supplyChain": 0, "quality": 0.25, "license": None},
        },
        "updated_packages": {
            "id": "updated-id",
            "name": "changed-package",
            "version": "2.0.0",
            "ecosystem": "pypi",
            "direct": True,
            "author": ["Fictional Maintainer"],
            "size": 23,
            "transitives": 4,
            "introduced_by": [("fictional-root", "requirements.txt")],
            "capabilities": [],
            "is_new": False,
            "author_url": "[Fictional Maintainer](https://socket.dev/pypi/user/Fictional Maintainer)",
            "url": "https://socket.dev/pypi/package/changed-package/overview/2.0.0",
            "purl": "changed-package@2.0.0",
            "scores": {"overall": 1, "maintenance": 0.5},
        },
        "removed_packages": {
            "id": "removed-id",
            "name": "removed-package",
            "version": "3.0.0",
            "ecosystem": "cargo",
            "direct": True,
            "author": ["Fictional Maintainer"],
            "size": 23,
            "transitives": 4,
            "introduced_by": [("fictional-root", "requirements.txt")],
            "capabilities": [],
            "is_new": False,
            "author_url": "[Fictional Maintainer](https://socket.dev/cargo/user/Fictional Maintainer)",
            "url": "https://socket.dev/cargo/package/removed-package/overview/3.0.0",
            "purl": "removed-package@3.0.0",
            "scores": {"vulnerability": 0, "quality": 1, "overall": None},
        },
        "replaced_packages": {
            "id": "replaced-id",
            "name": "changed-package",
            "version": "1.0.0",
            "ecosystem": "pypi",
            "direct": True,
            "author": ["Fictional Maintainer"],
            "size": 23,
            "transitives": 4,
            "introduced_by": [("fictional-root", "requirements.txt")],
            "capabilities": [],
            "is_new": False,
            "author_url": "[Fictional Maintainer](https://socket.dev/pypi/user/Fictional Maintainer)",
            "url": "https://socket.dev/pypi/package/changed-package/overview/1.0.0",
            "purl": "changed-package@1.0.0",
            "scores": {"license": 0.75},
        },
    }
    for field, expected_row in expected.items():
        rows = report[field]
        assert isinstance(rows, list)
        assert len(rows) == 1
        row = rows[0]
        assert isinstance(row, dict)
        assert set(row) == expected_row_keys
        assert row == expected_row

    serialized = json.loads(json.dumps(report))
    assert serialized["new_packages"][0]["introduced_by"] == [
        ["fictional-root", "requirements.txt"]
    ]
    assert serialized["new_packages"][0]["scores"] == {
        "supplyChain": 0,
        "quality": 0.25,
        "license": None,
    }
    report["new_packages"][0]["scores"]["quality"] = 99
    report["new_packages"][0]["author"].append("Changed")
    report["new_packages"][0]["capabilities"].append("filesystem")
    report["new_packages"][0]["introduced_by"].append(("other", "other.txt"))
    assert added.scores == {"supplyChain": 0, "quality": 0.25, "license": None}
    assert added.author == ["Fictional Maintainer"]
    assert added.capabilities == ["network"]
    assert added.introduced_by == [("fictional-root", "requirements.txt")]
    for field, value in original.items():
        if field in {
            "new_packages",
            "updated_packages",
            "removed_packages",
            "replaced_packages",
        }:
            assert [package.__dict__ for package in getattr(diff, field)] == [
                package.__dict__ for package in value
            ]
        else:
            assert getattr(diff, field) == value


def test_package_change_lists_keep_order_multiplicity_and_missing_scores():
    first = _purl("first", "shared", "1.0.0", "npm", namespace="@one")
    second = _purl("second", "shared", "1.0.0", "npm", namespace="@two")
    another = _purl("third", "shared", "2.0.0", "npm", namespace="@one")
    no_scores = _purl("no-scores", "bare", "1.0.0", "pypi", scores=None)
    diff = _diff()
    diff.new_packages = [first, second, first, another]
    diff.updated_packages = [no_scores]

    report = build_socket_json_report(diff, _config())

    assert [row["id"] for row in report["new_packages"]] == [
        "first",
        "second",
        "first",
        "third",
    ]
    assert [row["purl"] for row in report["new_packages"]] == [
        "@one/shared@1.0.0",
        "@two/shared@1.0.0",
        "@one/shared@1.0.0",
        "@one/shared@2.0.0",
    ]
    assert report["updated_packages"][0]["scores"] == {}


def test_package_change_lists_remain_independent_of_alert_selection():
    added = _purl("added", "dependency", "1.0.0", "npm")
    unchanged = _issue("Existing blocking alert", error=True)
    diff = _diff(new_alerts=[], unchanged_alerts=[unchanged])
    diff.new_packages = [added]
    diff.updated_packages = [_purl("updated", "dependency", "2.0.0", "npm")]
    diff.removed_packages = [_purl("removed", "dependency", "0.9.0", "npm")]
    diff.replaced_packages = [_purl("replaced", "dependency", "0.8.0", "npm")]

    ordinary = build_socket_json_report(diff, _config())
    strict = build_socket_json_report(diff, _config(strict_blocking=True))

    for field in (
        "new_packages",
        "updated_packages",
        "removed_packages",
        "replaced_packages",
    ):
        assert ordinary[field] == strict[field]
    assert ordinary["new_alerts"] == []
    assert strict["new_alerts"][0]["title"] == "Existing blocking alert"
    assert ordinary["scan_failed"] is False
    assert strict["scan_failed"] is True


def test_full_scan_package_inventory_does_not_become_change_lists():
    diff = _diff(is_full_scan=True)
    inventory_package = Package.from_socket_artifact(
        {
            "id": "inventory-id",
            "type": "npm",
            "name": "inventory-package",
            "version": "1.0.0",
            "alerts": [],
            "score": {},
            "topLevelAncestors": [],
        }
    )
    diff.packages = {"inventory-only": inventory_package}

    report = build_socket_json_report(diff, _config())

    assert report["new_packages"] == []
    assert report["updated_packages"] == []
    assert report["removed_packages"] == []
    assert report["replaced_packages"] == []
