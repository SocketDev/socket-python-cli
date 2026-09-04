"""What a full scan has to carry for each enabled output.

create_full_scan_with_report_url runs on every path with no baseline to compare
against: API mode, and (since 2.8.0) SCM branch pipelines. Fetching the SBOM is
the expensive part, so it is gated on the enabled outputs -- these pin which
outputs need it.
"""
import pytest
from socketdev.fullscans import FullScanParams

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.socket_config import SocketConfig


def _core(sdk, **cli_overrides):
    config = CliConfig.from_args(["--api-token", "test"])
    for key, value in cli_overrides.items():
        setattr(config, key, value)
    return Core(config=SocketConfig(api_key="test_key"), sdk=sdk, cli_config=config)


@pytest.fixture
def params():
    return FullScanParams(org_slug="test-org", repo="test", branch="main")


@pytest.fixture
def sdk(mock_sdk_with_responses):
    # get_license_text_via_purl iterates the response; the shared fixture leaves
    # purl.post as a bare MagicMock.
    mock_sdk_with_responses.purl.post.return_value = []
    return mock_sdk_with_responses


def test_license_generation_gets_the_package_list(sdk, params):
    """--generate-license enumerates diff.packages, not diff.new_alerts.

    Without this the attribution file for an SCM branch pipeline comes out empty.
    """
    core = _core(sdk, generate_license=True)

    diff = core.create_full_scan_with_report_url(
        ["."], params, explicit_files=["package.json"]
    )

    assert diff.packages
    # No alert-bearing output format is enabled, so alerts stay unfetched.
    assert diff.new_alerts == []


def test_license_details_are_requested_for_the_scanned_packages(sdk, params):
    core = _core(sdk, generate_license=True)

    core.create_full_scan_with_report_url(
        ["."], params, explicit_files=["package.json"]
    )

    components = sdk.purl.post.call_args.kwargs["components"]
    # Keyed the way the PURL endpoint echoes results back, not by artifact id.
    assert all(component["purl"].startswith("pkg:/") for component in components)
    assert any("@" in component["purl"] for component in components)


def test_alert_formats_still_fetch_the_sbom(sdk, params):
    core = _core(sdk, enable_json=True)

    diff = core.create_full_scan_with_report_url(
        ["."], params, explicit_files=["package.json"]
    )

    assert diff.packages
    # Alert-only outputs do not pay for the license lookup. (The scan fixture's
    # alerts carry no action, so none of them consolidate into new_alerts.)
    sdk.purl.post.assert_not_called()


def test_console_only_run_skips_the_sbom_fetch(sdk, params):
    core = _core(sdk)

    diff = core.create_full_scan_with_report_url(
        ["."], params, explicit_files=["package.json"]
    )

    assert diff.packages == {}
    assert diff.new_alerts == []
    sdk.fullscans.stream.assert_not_called()
