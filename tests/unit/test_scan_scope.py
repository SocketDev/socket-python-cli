from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from socketdev.exceptions import APIFailure
from socketdev.fullscans import FullScanParams

from socketsecurity.core import Core
from socketsecurity.core.classes import Diff


def _core() -> Core:
    core = Core.__new__(Core)
    core.config = SimpleNamespace(org_slug="example")
    core.cli_config = SimpleNamespace(
        disable_blocking=False,
        exit_code_on_api_error=0,
        generate_license=False,
    )
    core.sdk = MagicMock()
    return core


def test_multiple_scan_paths_are_uploaded_as_one_combined_full_scan(caplog):
    """Repeated --sub-path roots feed one graph, not independent scans."""
    core = _core()
    core.find_files = MagicMock(
        side_effect=[
            ["/repo/frontend/package.json"],
            ["/repo/backend/requirements.txt"],
        ]
    )
    core.resolve_base_full_scan_id = MagicMock(return_value="base-scan")
    core.create_full_scan = MagicMock(return_value=SimpleNamespace(id="new-scan"))
    core.get_added_and_removed_packages = MagicMock(return_value=({}, {}, {}))
    core.create_diff_report = MagicMock(return_value=Diff())
    params = FullScanParams(repo="repo-combined", branch="feature", scan_type="socket")
    params.include_license_details = True

    with caplog.at_level("INFO", logger="socketdev"):
        result = core.create_new_diff(
            ["/repo/frontend", "/repo/backend"],
            params,
            base_paths=["/repo"],
        )

    assert core.find_files.call_args_list == [
        (("/repo/frontend",),),
        (("/repo/backend",),),
    ]
    core.create_full_scan.assert_called_once_with(
        ["/repo/frontend/package.json", "/repo/backend/requirements.txt"],
        params,
        base_paths=["/repo"],
    )
    assert result.id == "new-scan"
    assert (
        'Scan configuration: repo="repo-combined" workspace=null '
        'scan_type="socket" roots=["frontend","backend"] manifests=2 '
        "manifest_source=discovered"
    ) in caplog.messages


def test_scan_configuration_omits_absolute_and_manifest_paths(caplog):
    params = FullScanParams(
        repo="repo-service",
        branch="feature",
        workspace="engineering",
    )

    with caplog.at_level("INFO", logger="socketdev"):
        Core._log_scan_configuration(
            ["/private/build/repo/service"],
            params,
            ["/private/build/repo/service/requirements.txt"],
            manifest_source="provided",
            base_paths=["/private/build/repo"],
        )

    message = caplog.messages[-1]
    assert 'workspace="engineering"' in message
    assert 'roots=["service"]' in message
    assert "manifests=1 manifest_source=provided" in message
    assert "/private/build" not in message
    assert "requirements.txt" not in message


def test_empty_baseline_logs_created_scan_id(caplog):
    core = _core()
    core.resolve_base_full_scan_id = MagicMock(return_value=None)
    core.create_full_scan = MagicMock(
        side_effect=[
            SimpleNamespace(id="empty-base"),
            SimpleNamespace(id="new-scan"),
        ]
    )
    core.get_added_and_removed_packages = MagicMock(return_value=({}, {}, {}))
    core.create_diff_report = MagicMock(return_value=Diff())
    params = FullScanParams(repo="repo-service", branch="feature")
    params.include_license_details = True

    with caplog.at_level("INFO", logger="socketdev"):
        core.create_new_diff(
            ["/repo/service"],
            params,
            base_paths=["/repo"],
            explicit_files=["/repo/service/requirements.txt"],
        )

    assert 'Baseline selected: source=empty scan_id="empty-base"' in caplog.messages


def test_full_scan_api_failure_propagates_for_cli_exit_code_mapping():
    core = _core()
    core.resolve_base_full_scan_id = MagicMock(return_value="base-scan")
    core.create_full_scan = MagicMock(side_effect=APIFailure("upload failed"))
    params = FullScanParams(repo="repo", branch="feature")
    params.include_license_details = True

    with pytest.raises(APIFailure, match="upload failed"):
        core.create_new_diff(
            ["/repo/workspace"],
            params,
            explicit_files=["/repo/workspace/package.json"],
        )


def test_diff_api_failure_propagates_for_cli_exit_code_mapping(caplog):
    core = _core()
    core.get_diff_scan_artifacts = MagicMock(side_effect=RuntimeError("poll failed"))
    core.sdk.fullscans.stream_diff.side_effect = APIFailure("comparison failed")

    with caplog.at_level("INFO", logger="socketdev"):
        with pytest.raises(APIFailure, match="comparison failed"):
            core.get_added_and_removed_packages("base-scan", "new-scan")

    assert (
        "Diff comparison mode: requested=diff-scan effective=streaming "
        "reason=RuntimeError"
    ) in caplog.messages
