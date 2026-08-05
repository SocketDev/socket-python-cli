import pytest
from socketdev.fullscans import FullScanParams

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.socket_config import SocketConfig


@pytest.fixture
def core(mock_sdk_with_responses):
    config = SocketConfig(api_key="test_key")
    return Core(config=config, sdk=mock_sdk_with_responses)


def make_cli_config(*extra_args):
    return CliConfig.from_args(["--api-token", "test-token", "--repo", "test", *extra_args])


def make_full_scan_params(**overrides):
    values = {
        "repo": "test",
        "branch": "main",
        "commit_hash": "head123",
        "scan_type": "socket",
        "workspace": None,
    }
    values.update(overrides)
    return FullScanParams(**values)


def test_get_repo_info(core, mock_sdk_with_responses):
    """Test getting repository information"""
    repo_info = core.get_repo_info("test")
    
    # Assert SDK called correctly
    mock_sdk_with_responses.repos.repo.assert_called_once_with(
        core.config.org_slug,
        "test",
        use_types=True,
    )
    
    # Assert response processed correctly
    assert repo_info.id == "f639d6c9-acc3-4d8a-9fb5-2090ad651c7e"
    assert repo_info.head_full_scan_id == "head"

def test_get_head_scan_for_repo(core, mock_sdk_with_responses):
    """Test getting head scan ID for a repository"""
    head_scan_id = core.get_head_scan_for_repo("test")
    
    # Assert SDK method called correctly
    mock_sdk_with_responses.repos.repo.assert_called_once_with(
        core.config.org_slug,
        "test",
        use_types=True,
    )
    
    # Assert we got the expected head scan ID
    assert head_scan_id == "head"

def test_get_head_scan_for_repo_no_head(core, mock_sdk_with_responses):
    """Test getting head scan ID for repo with no head scan"""
    head_scan_id = core.get_head_scan_for_repo("no-head")
    assert head_scan_id is None

def test_get_full_scan_id_by_commit(core, mock_sdk_with_responses):
    """Looks up the newest full scan for a repo + commit via the list endpoint"""
    mock_sdk_with_responses.fullscans.get.return_value = {
        "results": [{"id": "base-scan-id", "commit_hash": "abc123"}],
        "nextPage": None,
    }

    scan_id = core.get_full_scan_id_by_commit("test", "abc123")

    assert scan_id == "base-scan-id"
    mock_sdk_with_responses.fullscans.get.assert_called_once_with(
        core.config.org_slug,
        {
            "repo": "test",
            "commit_hash": "abc123",
            "sort": "created_at",
            "direction": "desc",
            "per_page": 1,
        },
    )


def test_get_full_scan_id_by_commit_scopes_to_workspace_and_scan_type(core, mock_sdk_with_responses):
    """Looks up a baseline scan from the same workspace and scan type as the new scan"""
    mock_sdk_with_responses.fullscans.get.return_value = {
        "results": [{"id": "workspace-reach-base", "commit_hash": "abc123"}],
        "nextPage": None,
    }

    scan_id = core.get_full_scan_id_by_commit(
        "test",
        "abc123",
        workspace="customer-a",
        scan_type="socket_tier1",
    )

    assert scan_id == "workspace-reach-base"
    mock_sdk_with_responses.fullscans.get.assert_called_once_with(
        core.config.org_slug,
        {
            "repo": "test",
            "commit_hash": "abc123",
            "sort": "created_at",
            "direction": "desc",
            "per_page": 1,
            "workspace": "customer-a",
            "scan_type": "socket_tier1",
        },
    )


def test_get_full_scan_id_by_commit_not_found(core, mock_sdk_with_responses):
    """No scan for the commit returns None (empty results and SDK error dict)"""
    mock_sdk_with_responses.fullscans.get.return_value = {"results": [], "nextPage": None}
    assert core.get_full_scan_id_by_commit("test", "abc123") is None

    mock_sdk_with_responses.fullscans.get.return_value = {}
    assert core.get_full_scan_id_by_commit("test", "abc123") is None

def test_resolve_base_full_scan_id_defaults_to_head_scan(core):
    """Without base overrides the repository head scan is the baseline"""
    assert core.resolve_base_full_scan_id(make_full_scan_params()) == "head"

def test_resolve_base_full_scan_id_uses_base_scan_id(core):
    """--base-scan-id is used verbatim, without touching the repo endpoint"""
    core.cli_config = make_cli_config("--base-scan-id", "explicit-base")

    assert core.resolve_base_full_scan_id(make_full_scan_params()) == "explicit-base"
    core.sdk.repos.repo.assert_not_called()

def test_resolve_base_full_scan_id_uses_base_commit_sha(core):
    """--base-commit-sha resolves through the full-scans list endpoint"""
    core.cli_config = make_cli_config("--base-commit-sha", "abc123")
    core.sdk.fullscans.get.return_value = {
        "results": [{"id": "merge-base-scan"}],
        "nextPage": None,
    }

    params = make_full_scan_params(workspace="customer-a", scan_type="socket_tier1")

    assert core.resolve_base_full_scan_id(params) == "merge-base-scan"
    core.sdk.repos.repo.assert_not_called()
    core.sdk.fullscans.get.assert_called_once_with(
        core.config.org_slug,
        {
            "repo": "test",
            "commit_hash": "abc123",
            "sort": "created_at",
            "direction": "desc",
            "per_page": 1,
            "workspace": "customer-a",
            "scan_type": "socket_tier1",
        },
    )

def test_resolve_base_full_scan_id_commit_sha_not_found_exits(core):
    """A --base-commit-sha with no scan is a hard error (exit_code_on_api_error)"""
    core.cli_config = make_cli_config("--base-commit-sha", "abc123")
    core.sdk.fullscans.get.return_value = {"results": [], "nextPage": None}

    with pytest.raises(SystemExit) as exc_info:
        core.resolve_base_full_scan_id(make_full_scan_params())
    assert exc_info.value.code == core.cli_config.exit_code_on_api_error

def test_resolve_base_full_scan_id_commit_sha_not_found_disable_blocking(core):
    """--disable-blocking keeps the missing-base error from failing the build"""
    core.cli_config = make_cli_config("--base-commit-sha", "abc123", "--disable-blocking")
    core.sdk.fullscans.get.return_value = {"results": [], "nextPage": None}

    with pytest.raises(SystemExit) as exc_info:
        core.resolve_base_full_scan_id(make_full_scan_params())
    assert exc_info.value.code == 0

def test_get_full_scan(core, mock_sdk_with_responses, head_scan_metadata, head_scan_stream):
    """Test getting an existing full scan"""
    full_scan = core.get_full_scan("head")
    
    # Assert SDK methods called correctly
    mock_sdk_with_responses.fullscans.metadata.assert_called_once_with(
        core.config.org_slug,
        "head",
        use_types=True,
    )
    mock_sdk_with_responses.fullscans.stream.assert_called_once_with(
        core.config.org_slug,
        "head",
        use_types=True,
    )
    
    # Assert response processed correctly
    assert full_scan.id == head_scan_metadata["data"]["id"]
    assert len(full_scan.sbom_artifacts) == len(head_scan_stream.artifacts)
    assert len(full_scan.packages) == len(head_scan_stream.artifacts)
    assert full_scan.packages["dp1"].transitives == 2

def test_create_full_scan(core, mock_sdk_with_responses, new_scan_metadata):
    """Test creating a new full scan"""
    # Setup test data
    files = ["requirements.txt"]
    params = FullScanParams(
        repo="test-repo",
        branch="main",
        commit_hash="abc123",
    )
    
    # Create the full scan
    full_scan = core.create_full_scan(files, params)
    
    # Verify the response
    assert full_scan.id == new_scan_metadata["data"]["id"]
    mock_sdk_with_responses.fullscans.post.assert_called_once_with(
        files,
        params,
        use_types=True,
        use_lazy_loading=True,
        max_open_files=50,
        base_paths=None,
    )

def test_get_added_and_removed_packages(core):
    """Test getting added and removed packages between two scans"""
    # Get two different scans to compare
    added, removed, all_packages = core.get_added_and_removed_packages("head", "new")
    
    # Verify SDK was called correctly.
    # include_license_details defaults to "false": the diff path never consumes
    # embedded license data (license artifacts come from the PURL endpoint), so
    # requesting it only bloats the response and risks the truncation
    # crash on large repos.
    core.sdk.fullscans.stream_diff.assert_called_once_with(
        core.config.org_slug,
        "head",
        "new",
        use_types=True,
        include_license_details="false",
    )
    
    # Verify the results
    # Added packages
    assert len(added) > 0  # We should have some added packages
    assert "dp3" in added  # Verify specific package we know was added
    assert "dp4" in added
    
    # Removed packages
    assert len(removed) > 0  # We should have some removed packages
    assert "dp2" in removed  # Verify specific package we know was removed
    assert "dp2_t1" in removed  # Verify transitive dependencies are also tracked
    assert "pypi/direct_package_1@1.6.0" in all_packages  # Unchanged package is in full package map

def test_get_added_and_removed_packages_license_override(core):
    """The include_license_details override seam still works when explicitly requested."""
    core.get_added_and_removed_packages("head", "new", include_license_details=True)

    core.sdk.fullscans.stream_diff.assert_called_once_with(
        core.config.org_slug,
        "head",
        "new",
        use_types=True,
        include_license_details="true",
    )

def test_empty_alerts_preserved(core):
    """Test that empty alerts arrays stay as empty arrays and don't become None"""
    # Get the scan that contains dp2 (which has empty alerts array)
    head_scan = core.get_full_scan("head")
    
    # Check the raw artifact first
    artifacts = core.get_sbom_data("head")
    assert artifacts["dp2"].alerts == []  # Should be empty list, not None
    
    # Check the final package
    assert head_scan.packages["dp2"].alerts == []  # Should still be empty list
