import pytest
from socketdev.fullscans import FullScanParams

from socketsecurity.core import Core
from socketsecurity.core.socket_config import SocketConfig


@pytest.fixture
def core(mock_sdk_with_responses):
    config = SocketConfig(api_key="test_key")
    return Core(config=config, sdk=mock_sdk_with_responses)

def test_get_repo_info(core, mock_sdk_with_responses):
    """Test getting repository information"""
    repo_info = core.get_repo_info("test")
    
    # Assert SDK called correctly
    mock_sdk_with_responses.repos.repo.assert_called_once_with(
        core.config.org_slug, 
        "test"
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
        "test"
    )
    
    # Assert we got the expected head scan ID
    assert head_scan_id == "head"

def test_get_head_scan_for_repo_no_head(core, mock_sdk_with_responses):
    """Test getting head scan ID for repo with no head scan"""
    head_scan_id = core.get_head_scan_for_repo("no-head")
    assert head_scan_id is None

def test_get_full_scan(core, mock_sdk_with_responses, head_scan_metadata, head_scan_stream):
    """Test getting an existing full scan"""
    full_scan = core.get_full_scan("head")
    
    # Assert SDK methods called correctly
    mock_sdk_with_responses.fullscans.metadata.assert_called_once_with(
        core.config.org_slug, 
        "head"
    )
    mock_sdk_with_responses.fullscans.stream.assert_called_once_with(
        core.config.org_slug, 
        "head"
    )
    
    # Assert response processed correctly
    assert full_scan.id == head_scan_metadata["data"]["id"]
    assert len(full_scan.sbom_artifacts) == len(head_scan_stream.artifacts)
    assert len(full_scan.packages) == len(head_scan_stream.artifacts)
    assert full_scan.packages["dp1"].transitives == 2

def test_create_full_scan(core, new_scan_metadata, new_scan_stream):
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
    assert len(full_scan.sbom_artifacts) == len(new_scan_stream.artifacts)
    assert len(full_scan.packages) == len(new_scan_stream.artifacts)
    assert full_scan.packages["dp4"].transitives == 1
    assert full_scan.packages["dp3"].transitives == 3

def test_get_added_and_removed_packages(core):
    """Test getting added and removed packages between two scans"""
    # Get two different scans to compare
    head_scan = core.get_full_scan("head")
    new_scan = core.get_full_scan("new")
    
    # Get the differences
    added, removed = core.get_added_and_removed_packages(head_scan, new_scan)
    
    # Verify SDK was called correctly
    core.sdk.fullscans.stream_diff.assert_called_once_with(
        core.config.org_slug,
        "head",
        "new"
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

def test_empty_alerts_preserved(core):
    """Test that empty alerts arrays stay as empty arrays and don't become None"""
    # Get the scan that contains dp2 (which has empty alerts array)
    head_scan = core.get_full_scan("head")
    
    # Check the raw artifact first
    artifacts = core.get_sbom_data("head")
    assert artifacts["dp2"].alerts == []  # Should be empty list, not None
    
    # Check the final package
    assert head_scan.packages["dp2"].alerts == []  # Should still be empty list
