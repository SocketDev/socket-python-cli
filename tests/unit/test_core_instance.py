import pytest
from unittest.mock import MagicMock
from socketsecurity.core import Core
from socketsecurity.core.config import SocketConfig
from socketsecurity.core.client import CliClient
from socketsecurity.core.classes import Package, Alert, FullScan, FullScanParams

from socketsecurity.core.exceptions import APIResourceNotFound
from unittest import mock
import json

@pytest.fixture
def mock_config():
    """Fixture for a mocked SocketConfig"""
    config = SocketConfig(api_key="test-key")
    config.org_slug = "test-org"
    config.org_id = "test-id"
    config.repository_path = "orgs/test-org/repos"
    # Add mock issues for capabilities
    class MockIssueProps:
        description = "Test description"
        title = "Test title"
        suggestion = "Test suggestion"
        nextStepTitle = "Test next step"

    config.all_issues.envVars = MockIssueProps()
    config.all_issues.networkAccess = MockIssueProps()
    config.security_policy = {
        'envVars': {'action': 'warn'},
        'networkAccess': {'action': 'error'}
    }
    return config

@pytest.fixture
def mock_client():
    """Fixture for a mocked CliClient"""
    client = MagicMock(spec=CliClient)
    client.request.return_value = MagicMock()  # Ensure request always returns a MagicMock
    return client

@pytest.fixture
def core_instance(mock_config, mock_client):
    """Fixture for a Core instance with mocked dependencies"""
    # Prevent set_org_vars from running in __init__
    with mock.patch('socketsecurity.core.Core.set_org_vars'):
        instance = Core(mock_config, mock_client)
    return instance

def test_create_issue_alerts(core_instance):
    """Test creation of issue alerts with different scenarios"""
    # Create mock issue properties
    class MockVulnProps:
        description = "Known vulnerability found"
        title = "Vulnerability Alert"
        suggestion = "Update package"
        nextStepTitle = "Fix Now"

    # Set up the mock issues
    core_instance.config.all_issues.knownVulnerability = MockVulnProps()
    core_instance.config.security_policy = {'knownVulnerability': {'action': 'error'}}

    # Create test package with Alert objects instead of dicts
    package = Package(
        id="test-pkg",
        name="test-package",
        version="1.0.0",
        type="npm",
        direct=True,
        manifestFiles=[{"file": "package.json"}],
        alerts=[
            Alert(
                type="knownVulnerability",
                severity="high",
                key="vuln-1",
                props={"details": "CVE-2023-1234"}
            ),
            Alert(
                type="licenseSpdxDisj",
                severity="low",
                key="license-1",
                props={}
            )
        ],
        purl="pkg:npm/test-package@1.0.0",
        url="https://example.com"
    )

    packages = {"test-pkg": package}
    alerts = {}

    # Test alert creation
    result = core_instance.create_issue_alerts(package, alerts, packages)

    # Verify results
    assert len(result) == 1
    assert "vuln-1" in result

    created_alert = result["vuln-1"][0]
    assert created_alert.type == "knownVulnerability"
    assert created_alert.severity == "high"
    assert created_alert.description == "Known vulnerability found"
    assert created_alert.title == "Vulnerability Alert"
    assert created_alert.suggestion == "Update package"
    assert created_alert.next_step_title == "Fix Now"
    assert created_alert.error is True
    assert created_alert.purl == "pkg:npm/test-package@1.0.0"

def test_get_org_id_slug_single_org(core_instance, mock_client):
    """Test getting org ID and slug when there is a single organization"""
    # Setup mock response
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "organizations": {
            "org123": {"slug": "test-org"}
        }
    }
    mock_client.request.return_value = mock_response

    # Test the method
    org_id, org_slug = core_instance.get_org_id_slug()

    # Verify results
    assert org_id == "org123"
    assert org_slug == "test-org"
    mock_client.request.assert_called_once_with("organizations")

def test_get_org_id_slug_no_orgs(core_instance, mock_client):
    """Test getting org ID and slug when there are no organizations"""
    # Setup mock response
    mock_response = MagicMock()
    mock_response.json.return_value = {"organizations": {}}
    mock_client.request.return_value = mock_response

    # Test the method
    org_id, org_slug = core_instance.get_org_id_slug()

    # Verify results
    assert org_id is None
    assert org_slug is None
    mock_client.request.assert_called_once_with("organizations")

def test_set_org_vars(core_instance, mock_client):
    """Test setting organization variables"""
    # Reset mock before test
    mock_client.reset_mock()

    # Setup mock responses
    org_response = MagicMock()
    org_response.json.return_value = {
        "organizations": {
            "org123": {"slug": "test-org"}
        }
    }

    security_response = MagicMock()
    security_response.json.return_value = {
        "defaults": {
            "issueRules": {
                "rule1": {"action": "warn"}
            }
        },
        "entries": [
            {
                "settings": {
                    "organization": {
                        "issueRules": {
                            "rule2": {"action": "error"}
                        }
                    }
                }
            }
        ]
    }

    # Setup mock client to return different responses for different calls
    def mock_request(path, **kwargs):
        if path == "organizations":
            return org_response
        elif path == "settings":
            return security_response
        raise ValueError(f"Unexpected path: {path}")

    mock_client.request.side_effect = mock_request

    # Test the method
    core_instance.set_org_vars()

    # Verify results
    assert core_instance.config.org_id == "org123"  # From organizations API response
    assert core_instance.config.org_slug == "test-org"

    expected_base_path = "orgs/test-org"
    assert core_instance.config.full_scan_path == f"{expected_base_path}/full-scans"
    assert core_instance.config.repository_path == f"{expected_base_path}/repos"

    assert core_instance.config.security_policy == {
        "rule1": {"action": "warn"},
        "rule2": {"action": "error"}
    }

    # Verify API calls
    expected_calls = [
        mock.call("organizations"),
        mock.call(
            path="settings",
            method="POST",
            payload=json.dumps([{"organization": "org123"}])  # Using org_id from organizations API response
        )
    ]
    mock_client.request.assert_has_calls(expected_calls, any_order=False)

def test_get_security_policy(core_instance, mock_client):
    """Test getting security policy with different scenarios"""
    # Reset mock before test
    mock_client.reset_mock()

    # Setup mock response
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "defaults": {
            "issueRules": {
                "rule1": {"action": "warn"},
                "rule3": {"action": "ignore"}
            }
        },
        "entries": [
            {
                "settings": {
                    "organization": {
                        "issueRules": {
                            "rule1": {"action": "error"},  # Override default
                            "rule2": {"action": "warn"}    # New rule
                        }
                    }
                }
            }
        ]
    }
    mock_client.request.return_value = mock_response

    # Test the method
    result = core_instance.get_security_policy()

    # Verify results
    expected_policy = {
        "rule1": {"action": "error"},  # Org rule overrides default
        "rule2": {"action": "warn"},   # Org-specific rule
        "rule3": {"action": "ignore"}  # Default rule (no override)
    }
    assert result == expected_policy

    # Verify API call
    mock_client.request.assert_called_once_with(
        path="settings",
        method="POST",
        payload=json.dumps([{"organization": core_instance.config.org_id}])
    )

def test_get_sbom_data(core_instance, mock_client):
    """Test getting SBOM data with different response scenarios"""
    # Reset mock before test
    mock_client.reset_mock()

    # Test case 1: Happy path with multiple packages
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = (
        '{"type":"pypi","name":"click","version":"8.1.7","id":"12453","topLevelAncestors":["6381179126"]}\n'
        '{"type":"pypi","name":"chardet","version":"5.2.0","id":"25259","topLevelAncestors":["6381179126"]}\n'
        '\n'  # Empty line should be skipped
        '"'    # Quote should be skipped
    )
    mock_client.request.return_value = mock_response

    result = core_instance.get_sbom_data("test-scan-id")

    assert len(result) == 2
    assert result[0]["name"] == "click"
    assert result[1]["name"] == "chardet"
    mock_client.request.assert_called_once_with("orgs/test-org/full-scans/test-scan-id")

    # Test case 2: Failed API response
    mock_client.reset_mock()
    mock_response.status_code = 404
    mock_response.text = "Not found"

    result = core_instance.get_sbom_data("bad-scan-id")

    assert result == []
    mock_client.request.assert_called_once()

    # Test case 3: Empty response
    mock_client.reset_mock()
    mock_response.status_code = 200
    mock_response.text = ""

    result = core_instance.get_sbom_data("empty-scan-id")

    assert result == []
    mock_client.request.assert_called_once()

def test_create_sbom_output(core_instance, mock_client):
    """Test creating SBOM output with different scenarios"""
    # Reset mock before test
    mock_client.reset_mock()

    # Create mock diff object
    class MockDiff:
        id = "test-diff-id"

    diff = MockDiff()

    # Test case 1: Successful JSON response
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "type": "library",
                "name": "test-package",
                "version": "1.0.0"
            }
        ]
    }
    mock_client.request.return_value = mock_response

    result = core_instance.create_sbom_output(diff)

    assert result == mock_response.json.return_value
    mock_client.request.assert_called_once_with(
        path="orgs/test-org/export/cdx/test-diff-id"
    )

    # Test case 2: JSON parsing error
    mock_client.reset_mock()
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)

    result = core_instance.create_sbom_output(diff)

    assert result == {}  # Should return empty dict on error
    mock_client.request.assert_called_once_with(
        path="orgs/test-org/export/cdx/test-diff-id"
    )

def test_create_full_scan(core_instance, mock_client, tmp_path):
    """Test creating full scan with different scenarios"""
    # Reset mock before test
    mock_client.reset_mock()

    # Set up the full scan path in config
    core_instance.config.full_scan_path = "orgs/test-org/full-scans"

    # Create test files and store their full paths
    workspace = str(tmp_path)
    test_files = []
    file_contents = {
        "package.json": "{}",
        "nested/package.json": "{}",
        "requirements.txt": "requests==2.0.0"
    }

    for rel_path, content in file_contents.items():
        full_path = tmp_path / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)
        test_files.append(str(full_path))

    # Create test params
    class MockParams:
        repo = "test-repo"
        branch = "main"
        commit = "abc123"
        message = "test commit"
        pr = None

    params = MockParams()

    # Test case 1: Successful scan with multiple files
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": "scan123",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
        "organization_id": "org123",
        "repository_id": "repo123",
        "branch": "main",
        "commit_message": "test commit",
        "commit_hash": "abc123",
        "pull_request": None
    }

    sbom_response = MagicMock()
    sbom_response.status_code = 200
    sbom_response.text = (
        '{"type":"npm","name":"test-pkg","version":"1.0.0","id":"12453","license":"MIT","direct":true,"manifestFiles":[{"file":"package.json"}]}\n'
        '{"type":"pypi","name":"requests","version":"2.0.0","id":"25259","license":"Apache-2.0","direct":true,"manifestFiles":[{"file":"requirements.txt"}]}\n'
    )

    def mock_request(path, **kwargs):
        if "orgs/test-org/full-scans?" in path:  # Creating new scan
            return mock_response
        elif "orgs/test-org/full-scans/scan123" in path:  # Getting SBOM data
            return sbom_response
        raise ValueError(f"Unexpected path: {path}")

    mock_client.request.side_effect = mock_request

    # Test the method
    result = core_instance.create_full_scan(test_files, params, workspace)

    # Verify results
    assert isinstance(result, FullScan)
    assert result.id == "scan123"
    assert result.branch == "main"
    assert result.commit_hash == "abc123"
    assert len(result.sbom_artifacts) == 2
    assert result.sbom_artifacts[0]["name"] == "test-pkg"
    assert result.sbom_artifacts[1]["name"] == "requests"

    # Verify API calls
    assert mock_client.request.call_count == 2
    create_call = mock_client.request.call_args_list[0]

    # Check the first positional argument (path)
    assert "orgs/test-org/full-scans?" in create_call[0][0]
    assert create_call[1]["method"] == "POST"
    assert len(create_call[1]["files"]) == 3  # All test files included

    # Verify file paths in request are relative to workspace
    files_in_request = [f[0] for f in create_call[1]["files"]]
    assert "package.json" in files_in_request
    assert "nested/package.json" in files_in_request
    assert "requirements.txt" in files_in_request

    # Test case 2: Empty file list
    mock_client.reset_mock()
    def mock_request_empty_files(path, **kwargs):
        if "orgs/test-org/full-scans?" in path:  # Creating new scan
            response = MagicMock()
            response.status_code = 400
            response.json.return_value = {
                "id": None,
                "error": "No files provided"
            }
            return response
        elif "orgs/test-org/full-scans/None" in path:  # Getting SBOM data for failed scan
            response = MagicMock()
            response.status_code = 404
            response.text = ""
            return response
        raise ValueError(f"Unexpected path: {path}")

    mock_client.request.side_effect = mock_request_empty_files

    result = core_instance.create_full_scan([], params, workspace)
    assert result.id is None
    assert result.sbom_artifacts == []  # Empty list for failed scan

    # Test case 3: Failed API response
    mock_client.reset_mock()
    def mock_request_failed_api(path, **kwargs):
        if "orgs/test-org/full-scans?" in path:  # Creating new scan
            response = MagicMock()
            response.status_code = 500
            response.json.return_value = {
                "id": None,
                "error": "Server error"
            }
            return response
        elif "orgs/test-org/full-scans/None" in path:  # Getting SBOM data for failed scan
            response = MagicMock()
            response.status_code = 404
            response.text = ""
            return response
        raise ValueError(f"Unexpected path: {path}")

    mock_client.request.side_effect = mock_request_failed_api

    result = core_instance.create_full_scan(test_files, params, workspace)
    assert result.id is None
    assert result.sbom_artifacts == []  # Empty list for failed scan

def test_get_head_scan_for_repo(core_instance, mock_client):
    """Test getting head scan ID for a repository with different scenarios"""
    # Reset mock before test
    mock_client.reset_mock()

    # Set up the repository path in config
    core_instance.config.repository_path = "orgs/test-org/repos"

    # Test case 1: Repository exists with head scan
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "repository": {
            "id": "repo123",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "head_full_scan_id": "scan123",
            "name": "test-repo",
            "description": "Test repository",
            "homepage": "https://example.com",
            "visibility": "public",
            "archived": False,
            "default_branch": "main"
        }
    }
    mock_client.request.return_value = mock_response

    result = core_instance.get_head_scan_for_repo("test-repo")

    assert result == "scan123"
    mock_client.request.assert_called_once_with("orgs/test-org/repos/test-repo")

    # Test case 2: Repository exists but no head scan
    mock_client.reset_mock()
    mock_response.json.return_value = {
        "repository": {
            "id": "repo123",
            "head_full_scan_id": None,
            # ... other fields omitted for brevity
        }
    }

    result = core_instance.get_head_scan_for_repo("test-repo")

    assert result is None
    mock_client.request.assert_called_once()

    # Test case 3: Repository not found
    mock_client.reset_mock()
    mock_response.status_code = 404
    mock_response.json.side_effect = APIResourceNotFound("Repository not found")
    mock_client.request.side_effect = APIResourceNotFound("Repository not found")

    with pytest.raises(APIResourceNotFound) as exc_info:
        core_instance.get_head_scan_for_repo("nonexistent-repo")

    assert "Repository not found" in str(exc_info.value)
    mock_client.request.assert_called_once()

def test_get_full_scan(core_instance, mock_client):
    """Test getting full scan data with different scenarios"""
    mock_client.reset_mock()
    core_instance.config.full_scan_path = "orgs/test-org/full-scans"

    # Test case 1: Successful scan with SBOM data
    mock_scan_response = MagicMock()
    mock_scan_response.status_code = 200
    mock_scan_response.json.return_value = {
        "id": "scan123",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
        "organization_id": "org123",
        "repository_id": "repo123",
        "branch": "main",
        "commit_message": "test commit",
        "commit_hash": "abc123",
        "pull_request": None
    }

    # Second request should return SBOM data
    mock_sbom_response = MagicMock()
    mock_sbom_response.status_code = 200
    mock_sbom_response.text = (
        '{"type":"npm","name":"test-pkg","version":"1.0.0","id":"12453","license":"MIT","direct":true,"manifestFiles":[{"file":"package.json"}]}\n'
        '{"type":"pypi","name":"requests","version":"2.0.0","id":"25259","license":"Apache-2.0","direct":true,"manifestFiles":[{"file":"requirements.txt"}]}\n'
    )

    call_count = 0
    def mock_request(path, **kwargs):
        nonlocal call_count
        print(f"Mock request called with path: {path}, kwargs: {kwargs}")
        if path == f"{core_instance.config.full_scan_path}/scan123":
            call_count += 1
            if call_count == 1:  # First call returns scan data
                print("Returning scan response")
                return mock_scan_response
            else:  # Second call returns SBOM data
                print("Returning SBOM response")
                return mock_sbom_response
        raise ValueError(f"Unexpected path: {path}")

    mock_client.request.side_effect = mock_request

    result = core_instance.get_full_scan("scan123")
    print(f"Result SBOM artifacts: {result.sbom_artifacts}")

    assert isinstance(result, FullScan)
    assert result.id == "scan123"
    assert result.branch == "main"
    assert result.commit_hash == "abc123"
    assert len(result.sbom_artifacts) == 2
    assert result.sbom_artifacts[0]["name"] == "test-pkg"
    assert result.sbom_artifacts[1]["name"] == "requests"

    # Test case 2: Scan not found
    mock_client.reset_mock()
    def mock_request_not_found(path, **kwargs):
        raise APIResourceNotFound("Scan not found")

    mock_client.request.side_effect = mock_request_not_found

    with pytest.raises(APIResourceNotFound) as exc_info:
        core_instance.get_full_scan("nonexistent-scan")

    assert "Scan not found" in str(exc_info.value)
    mock_client.request.assert_called_once()

    # Test case 3: Invalid response format
    mock_client.reset_mock()
    mock_scan_invalid = MagicMock()
    mock_scan_invalid.status_code = 200
    mock_scan_invalid.json.return_value = {
        "id": "scan123",
        # Missing required fields
    }

    def mock_request_invalid(path, **kwargs):
        return mock_scan_invalid

    mock_client.request.side_effect = mock_request_invalid

    result = core_instance.get_full_scan("scan123")

    # Should still create a FullScan object with default values
    assert isinstance(result, FullScan)
    assert result.id == "scan123"
    assert not hasattr(result, "branch")
    assert not hasattr(result, "commit_hash")
    assert result.sbom_artifacts == []  # Default empty list

def test_compare_sboms(core_instance, mock_client):
    """Test SBOM comparison with different scenarios"""
    print("Setting up test data...")

    # Add debug logging to see what's happening with alerts
    def create_package_dict(pkg_id, name, version, alerts=None):
        return {
            "id": pkg_id,
            "name": name,
            "version": version,
            "type": "npm",
            "direct": True,
            "license": "MIT",
            "manifestFiles": [{"file": "package.json"}],
            "alerts": [Alert(**alert) for alert in (alerts or [])],  # Convert to Alert objects here
            "author": ["Test Author"],
            "size": 1000,
            "url": f"https://example.com/{name}",
            "purl": f"pkg:npm/{name}@{version}",
            "topLevelAncestors": []
        }

    # Test case 1: New packages and alerts
    new_scan_data = [
        create_package_dict("pkg1", "test-pkg", "1.0.0", alerts=[
            {
                "type": "envVars",
                "severity": "high",
                "key": "env-1",
                "category": "capability",
                "props": {}
            }
        ]),
        create_package_dict("pkg2", "new-pkg", "2.0.0", alerts=[
            {
                "type": "networkAccess",
                "severity": "high",
                "key": "net-1",
                "category": "capability",
                "props": {}
            }
        ])
    ]

    head_scan_data = [
        create_package_dict("pkg1", "test-pkg", "1.0.0"),  # No alerts
        create_package_dict("pkg3", "removed-pkg", "3.0.0")  # No alerts
    ]

    print("Comparing SBOMs...")
    result = core_instance.compare_sboms(new_scan_data, head_scan_data)
    print(f"New packages: {result.new_packages}")
    print(f"Removed packages: {result.removed_packages}")
    print(f"New alerts: {result.new_alerts}")
    print(f"New capabilities: {result.new_capabilities}")

    # Verify new package was added
    assert len(result.new_packages) == 1
    assert result.new_packages[0].name == "new-pkg"

    # Verify package was removed
    assert len(result.removed_packages) == 1
    assert result.removed_packages[0].name == "removed-pkg"

    # Verify new alerts were detected
    assert len(result.new_alerts) > 0

    # Verify new capabilities were detected
    assert len(result.new_capabilities) > 0
    assert "Environment" in result.new_capabilities["pkg1"]
    assert "Network" in result.new_capabilities["pkg2"]

    # Additional assertions for alert handling
    assert any(alert.type == "envVars" for alert in result.new_alerts), "Should detect new envVars alert"
    assert any(alert.type == "networkAccess" for alert in result.new_alerts), "Should detect new networkAccess alert"

    # Verify alerts are properly created with all required fields
    for alert in result.new_alerts:
        assert hasattr(alert, 'key'), "Alert should have a key"
        assert hasattr(alert, 'severity'), "Alert should have severity"
        assert hasattr(alert, 'description'), "Alert should have description"
        assert hasattr(alert, 'title'), "Alert should have title"

def test_create_new_diff_no_change(core_instance, mock_client):
    """Test create_new_diff when no_change is True"""
    params = FullScanParams(
        repo="test-repo",
        branch="main",
        commit_message="test commit",
        commit_hash="abc123",
        pull_request=1,
        committer="test@example.com",
        make_default_branch=False,
        set_as_pending_head=False
    )

    result = core_instance.create_new_diff("test/path", params, "workspace", no_change=True)
    assert result.id == "no_diff_id"

def test_create_new_diff_no_files(core_instance, mock_client):
    """Test create_new_diff when no files are found"""
    params = FullScanParams(
        repo="test-repo",
        branch="main",
        commit_message="test commit",
        commit_hash="abc123",
        pull_request=1,
        committer="test@example.com",
        make_default_branch=False,
        set_as_pending_head=False
    )

    with mock.patch('socketsecurity.core.Core.find_files', return_value=[]):
        result = core_instance.create_new_diff("test/path", params, "workspace")
        assert result.id == "no_diff_id"

def test_create_new_diff_new_repository(core_instance, mock_client):
    """Test create_new_diff for a new repository (no head scan)"""
    params = FullScanParams(
        repo="test-repo",
        branch="main",
        commit_message="test commit",
        commit_hash="abc123",
        pull_request=1,
        committer="test@example.com",
        make_default_branch=False,
        set_as_pending_head=False
    )

    test_package = {
        "id": "test-pkg-1",
        "name": "test-pkg",
        "version": "1.0.0",
        "type": "npm",
        "direct": True,
        "license": "MIT",
        "manifestFiles": [{"file": "package.json"}],
        "alerts": [],
        "author": ["Test Author"],
        "size": 1000,
        "url": "https://example.com/test-pkg",
        "purl": "pkg:npm/test-pkg@1.0.0",
        "topLevelAncestors": []
    }

    # Mock the repository request to return 404
    mock_response = MagicMock()
    mock_response.json.return_value = {"error": "Not Found"}
    mock_response.status_code = 404
    mock_client.request.side_effect = [APIResourceNotFound("Repository not found")]

    with mock.patch('socketsecurity.core.Core.find_files', return_value=["package.json"]):
        with mock.patch('socketsecurity.core.Core.create_full_scan') as mock_create_scan:
            mock_create_scan.return_value = FullScan(
                id="new-scan-id",
                sbom_artifacts=[test_package]
            )
            result = core_instance.create_new_diff("test/path", params, "workspace")
            assert result.id == "new-scan-id"
            assert result.diff_url == result.report_url
            assert result.report_url == f"https://socket.dev/dashboard/org/{core_instance.config.org_slug}/sbom/new-scan-id"

def test_create_new_diff_existing_head_scan(core_instance, mock_client):
    """Test create_new_diff with an existing head scan"""
    params = FullScanParams(
        repo="test-repo",
        branch="main",
        commit_message="test commit",
        commit_hash="abc123",
        pull_request=1,
        committer="test@example.com",
        make_default_branch=False,
        set_as_pending_head=False
    )

    test_package = {
        "id": "test-pkg-1",
        "name": "test-pkg",
        "version": "1.0.0",
        "type": "npm",
        "direct": True,
        "license": "MIT",
        "manifestFiles": [{"file": "package.json"}],
        "alerts": [],
        "author": ["Test Author"],
        "size": 1000,
        "url": "https://example.com/test-pkg",
        "purl": "pkg:npm/test-pkg@1.0.0",
        "topLevelAncestors": []
    }

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "repository": {
            "id": "repo-123",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-02T00:00:00Z",
            "head_full_scan_id": "head-scan-id",
            "name": "test-repo",
            "description": "Test repository",
            "homepage": "https://example.com",
            "visibility": "public",
            "archived": False,
            "default_branch": "main"
        }
    }
    mock_client.request.return_value = mock_response

    with mock.patch('socketsecurity.core.Core.find_files', return_value=["package.json"]):
        with mock.patch('socketsecurity.core.Core.create_full_scan') as mock_create_scan:
            mock_create_scan.return_value = FullScan(
                id="new-scan-id",
                sbom_artifacts=[test_package]
            )
            result = core_instance.create_new_diff("test/path", params, "workspace")
            assert result.id == "new-scan-id"
            assert "head-scan-id" in result.diff_url

def test_create_new_diff_empty_head_scan(core_instance, mock_client):
    """Test create_new_diff with an empty head scan"""
    params = FullScanParams(
        repo="test-repo",
        branch="main",
        commit_message="test commit",
        commit_hash="abc123",
        pull_request=1,
        committer="test@example.com",
        make_default_branch=False,
        set_as_pending_head=False
    )

    test_package = {
        "id": "test-pkg-1",
        "name": "test-pkg",
        "version": "1.0.0",
        "type": "npm",
        "direct": True,
        "license": "MIT",
        "manifestFiles": [{"file": "package.json"}],
        "alerts": [],
        "author": ["Test Author"],
        "size": 1000,
        "url": "https://example.com/test-pkg",
        "purl": "pkg:npm/test-pkg@1.0.0",
        "topLevelAncestors": []
    }

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "repository": {
            "id": "repo-123",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-02T00:00:00Z",
            "head_full_scan_id": "",  # Empty head scan ID
            "name": "test-repo",
            "description": "Test repository",
            "homepage": "https://example.com",
            "visibility": "public",
            "archived": False,
            "default_branch": "main"
        }
    }
    mock_client.request.return_value = mock_response

    with mock.patch('socketsecurity.core.Core.find_files', return_value=["package.json"]):
        with mock.patch('socketsecurity.core.Core.create_full_scan') as mock_create_scan:
            mock_create_scan.return_value = FullScan(
                id="new-scan-id",
                sbom_artifacts=[test_package]
            )
            result = core_instance.create_new_diff("test/path", params, "workspace")
            assert result.id == "new-scan-id"
            assert result.diff_url == result.report_url
