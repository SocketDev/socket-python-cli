import json

from socketdev.fullscans import DiffArtifacts

from socketsecurity.core.alert_selection import clone_diff_with_selected_alerts
from socketsecurity.core.classes import Diff, Issue, Package
from socketsecurity.core.diff_result import (
    DiffScanResult,
    PackageComparisonResult,
    create_diff_scan_result,
)
from socketsecurity.core.messages import Messages


def test_diff_scan_ids_default_and_assignment():
    diff = Diff(id="NO_DIFF_RAN", report_url="", diff_url="")

    assert diff.new_scan_id is None
    assert diff.old_scan_id is None
    assert diff.diff_scan_id is None

    diff.set_scan_ids("new-scan", old_scan_id="old-scan", diff_scan_id="diff-resource")

    assert diff.id == "new-scan"
    assert diff.new_scan_id == "new-scan"
    assert diff.old_scan_id == "old-scan"
    assert diff.diff_scan_id == "diff-resource"

    no_scan = Diff(id="NO_SCAN_RAN", report_url="", diff_url="")
    assert no_scan.id == "NO_SCAN_RAN"
    assert no_scan.new_scan_id is None
    assert no_scan.old_scan_id is None
    assert no_scan.diff_scan_id is None


def test_streaming_and_temporary_baseline_assignments():
    streaming_diff = Diff()
    streaming_diff.set_scan_ids("new-scan", old_scan_id="old-scan")

    temporary_baseline_diff = Diff()
    temporary_baseline_diff.set_scan_ids(
        "new-scan",
        old_scan_id="actual-temporary-baseline-scan",
        diff_scan_id="server-diff",
    )

    assert streaming_diff.id == streaming_diff.new_scan_id == "new-scan"
    assert streaming_diff.old_scan_id == "old-scan"
    assert streaming_diff.diff_scan_id is None
    assert temporary_baseline_diff.old_scan_id == "actual-temporary-baseline-scan"
    assert temporary_baseline_diff.diff_scan_id == "server-diff"


def test_full_scan_assignment_clears_comparison_ids():
    diff = Diff()
    diff.set_scan_ids("comparison-new", old_scan_id="old", diff_scan_id="server-diff")

    diff.set_scan_ids("full-scan")

    assert diff.id == "full-scan"
    assert diff.new_scan_id == "full-scan"
    assert diff.old_scan_id is None
    assert diff.diff_scan_id is None


def test_artifact_result_normalizes_sdk_buckets_and_preserves_identity():
    def artifact(bucket: str) -> dict[str, str]:
        return {
            "id": f"{bucket}-artifact",
            "type": "npm",
            "name": f"{bucket}-sample",
            "version": "1.0.0",
            "diffType": bucket,
        }

    result = create_diff_scan_result(
        {
            "added": [artifact("added")],
            "removed": [artifact("removed")],
            "unchanged": [artifact("unchanged")],
            "replaced": [artifact("replaced")],
            "updated": [artifact("updated")],
        },
        "server-diff-id",
    )

    assert isinstance(result, DiffScanResult)
    assert result.diff_scan_id == "server-diff-id"
    assert isinstance(result.artifacts, DiffArtifacts)
    for bucket in ("added", "removed", "unchanged", "replaced", "updated"):
        assert [item.id for item in getattr(result.artifacts, bucket)] == [
            f"{bucket}-artifact"
        ]

    missing_bucket = create_diff_scan_result(
        {"added": [artifact("added")]}, "server-diff-id"
    )
    assert [item.id for item in missing_bucket.artifacts.added] == ["added-artifact"]
    assert missing_bucket.artifacts.removed == []
    assert missing_bucket.artifacts.unchanged == []
    assert missing_bucket.artifacts.replaced == []
    assert missing_bucket.artifacts.updated == []

    null_buckets = create_diff_scan_result(
        {
            "added": [artifact("added")],
            "removed": None,
            "unchanged": None,
            "replaced": None,
            "updated": None,
        },
        "server-diff-id",
    )
    assert null_buckets.artifacts.removed == []
    assert null_buckets.artifacts.unchanged == []
    assert null_buckets.artifacts.replaced == []
    assert null_buckets.artifacts.updated == []


def test_package_comparison_result_retains_maps_and_identity():
    package = Package(
        type="npm",
        name="sample",
        version="1.0.0",
        id="sample-id",
        score=None,
        alerts=[],
    )
    added = {"added": package}
    removed = {"removed": package}
    packages = {"all": package}

    result = PackageComparisonResult(added, removed, packages, None)

    assert result.added_packages is added
    assert result.removed_packages is removed
    assert result.packages is packages
    assert result.diff_scan_id is None


def test_alert_clone_preserves_scan_identity_and_no_run_absence():
    issue = Issue(title="selected")
    diff = Diff(
        id="new-scan",
        report_url="report",
        diff_url="comparison",
        new_alerts=[issue],
    )
    diff.set_scan_ids("new-scan", old_scan_id="old-scan", diff_scan_id="diff-resource")

    clone = clone_diff_with_selected_alerts(diff, [issue])
    no_run = Diff(id="NO_DIFF_RAN", report_url="", diff_url="")
    no_run_clone = clone_diff_with_selected_alerts(no_run, [])
    fallback = Diff(
        id="fallback-new-scan",
        report_url="fallback-report",
        diff_url="fallback-diff",
    )
    fallback.set_scan_ids("fallback-new-scan", old_scan_id="fallback-old-scan")
    fallback_clone = clone_diff_with_selected_alerts(fallback, [])

    assert clone.id == "new-scan"
    assert clone.new_scan_id == "new-scan"
    assert clone.old_scan_id == "old-scan"
    assert clone.diff_scan_id == "diff-resource"
    assert diff.new_alerts == [issue]
    assert fallback_clone.new_scan_id == "fallback-new-scan"
    assert fallback_clone.old_scan_id == "fallback-old-scan"
    assert fallback_clone.diff_scan_id is None
    assert no_run_clone.new_scan_id is None
    assert no_run_clone.old_scan_id is None
    assert no_run_clone.diff_scan_id is None


def test_identity_does_not_change_existing_serialized_output():
    diff = Diff(
        id="new-scan",
        report_url="report",
        diff_url="comparison",
        packages={},
    )
    diff.set_scan_ids("new-scan", old_scan_id="old-scan", diff_scan_id="server-diff")

    assert set(diff.to_dict()) == {
        "new_packages",
        "updated_packages",
        "new_capabilities",
        "removed_packages",
        "replaced_packages",
        "new_alerts",
        "unchanged_alerts",
        "removed_alerts",
        "id",
        "sbom",
        "packages",
        "report_url",
        "diff_url",
    }
    output = Messages.create_security_comment_json(diff)
    assert json.loads(json.dumps(output)) == {
        "scan_failed": False,
        "new_alerts": [],
        "full_scan_id": "new-scan",
        "diff_url": "comparison",
    }
