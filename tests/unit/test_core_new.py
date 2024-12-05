import pytest
from unittest import mock
from socketsecurity.core import Core
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.core.classes import FullScanParams

class MockFullscans:
    def stream(self, org_slug, scan_id):
        return {}

class MockOrg:
    def get(self):
        return {
            "organizations": {
                "org123": {"slug": "test-org"}
            }
        }

class MockSettings:
    def get(self, org_slug):
        return {
            "securityPolicyRules": {
                "envVars": {"action": "warn"},
                "networkAccess": {"action": "error"}
            }
        }

class MockExport:
    def cdx_bom(self, org_slug, diff_id):
        return {}

class MockRepos:
    def repo(self, org_slug, repo_slug):
        return {}

class MockSDK:
    def __init__(self):
        self.org = MockOrg()
        self.settings = MockSettings()
        self.fullscans = MockFullscans()
        self.export = MockExport()
        self.repos = MockRepos()

@pytest.fixture
def mock_socketdev():
    """Fixture for a mocked socketdev SDK"""
    return MockSDK()

@pytest.fixture
def mock_config():
    """Fixture for a mocked SocketConfig"""
    return SocketConfig(api_key="test-key")

@pytest.fixture
def core_instance(mock_config, mock_socketdev):
    """Fixture for a Core instance with mocked dependencies"""
    return Core(mock_config, mock_socketdev)

def test_set_org_vars(core_instance):
    """Test setting organization variables"""
    # Replace the SDK with our mock
    core_instance.sdk = MockSDK()

    # Call the method
    core_instance.set_org_vars()

    # Verify the config was updated correctly
    assert core_instance.config.org_id == "org123"
    assert core_instance.config.org_slug == "test-org"
    assert core_instance.config.full_scan_path == "orgs/test-org/full-scans"
    assert core_instance.config.repository_path == "orgs/test-org/repos"
    assert core_instance.config.security_policy == {
        "envVars": {"action": "warn"},
        "networkAccess": {"action": "error"}
    }

def test_core_initialization_with_security_policy(mock_config, mock_socketdev):
    """Test Core initialization sets security policy correctly"""
    # Set up the mock response for settings.get
    mock_socketdev.settings.get = lambda org_slug: {
        "securityPolicyRules": {
            "envVars": {"action": "warn"},
            "networkAccess": {"action": "error"},
            "shellAccess": {"action": "defer"}
        }
    }

    # Create a Core instance
    core_instance = Core(mock_config, mock_socketdev)

    # Verify the security policy is set correctly in the config
    assert core_instance.config.security_policy == {
        "envVars": {"action": "warn"},
        "networkAccess": {"action": "error"},
        "shellAccess": {"action": "defer"}
    }

def test_get_sbom_data_success(core_instance):
    """Test successful SBOM data retrieval"""
    # Mock successful response with sample package data
    core_instance.sdk.fullscans.stream = lambda org_slug, scan_id: {
        "success": True,
        "status": 200,
        "26172": {
            "type": "pypi",
            "name": "decorator",
            "version": "5.1.1",
            "id": "26172",
            "license": "BSD-2-Clause",
            "alerts": [
                {
                    "key": "QSDk_DyVLEPi46ctHQV0iGsRwjVR9_AzypswS74YQ4fg",
                    "type": "usesEval",
                    "severity": "middle"
                }
            ]
        },
        "26187": {
            "type": "pypi",
            "name": "stack-data",
            "version": "0.6.3",
            "id": "26187",
            "license": "MIT",
            "alerts": []
        }
    }

    result = core_instance.get_sbom_data("test-scan-id")

    # Verify the response is processed correctly
    assert len(result) == 2
    assert result["26172"]["name"] == "decorator"
    assert result["26187"]["name"] == "stack-data"
    assert "success" not in result  # Should be removed
    assert "status" not in result   # Should be removed

def test_get_sbom_data_failure(core_instance):
    """Test SBOM data retrieval failure"""
    # Mock failed response
    core_instance.sdk.fullscans.stream = lambda org_slug, scan_id: {
        "success": False,
        "status": 404,
        "message": "Scan not found"
    }

    result = core_instance.get_sbom_data("test-scan-id")

    # Verify empty list is returned on failure
    assert result == []

def test_create_sbom_output_success(core_instance):
    """Test successful SBOM output creation"""
    # Mock successful response with sample CycloneDX data
    core_instance.sdk.export.cdx_bom = lambda org_slug, diff_id: {
        "success": True,
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:c21ec048-9865-4b5a-a2c2-ef829f5609b3",
        "components": [
            {
                "group": "@babel",
                "name": "runtime",
                "version": "7.13.10",
                "licenses": [
                    {
                        "license": {
                            "id": "MIT",
                            "url": "https://opensource.org/licenses/MIT"
                        }
                    }
                ],
                "purl": "pkg:npm/%40babel/runtime@7.13.10",
                "type": "library"
            }
        ]
    }

    result = core_instance.create_sbom_output(mock.Mock(id="test-diff-id"))

    # Verify the response is processed correctly
    assert result["bomFormat"] == "CycloneDX"
    assert result["specVersion"] == "1.5"
    assert "success" not in result  # Should be removed
    assert len(result["components"]) == 1
    assert result["components"][0]["name"] == "runtime"

def test_create_sbom_output_failure(core_instance):
    """Test SBOM output creation failure"""
    # Mock failed response
    core_instance.sdk.export.cdx_bom = lambda org_slug, diff_id: {
        "success": False,
        "message": "Failed to generate SBOM"
    }

    result = core_instance.create_sbom_output(mock.Mock(id="test-diff-id"))

    # Verify empty dict is returned on failure
    assert result == {}

def test_create_sbom_output_exception(core_instance):
    """Test SBOM output creation with exception"""
    # Mock exception
    def raise_error(*args):
        raise Exception("API Error")

    core_instance.sdk.export.cdx_bom = raise_error

    result = core_instance.create_sbom_output(mock.Mock(id="test-diff-id"))

    # Verify empty dict is returned on exception
    assert result == {}

def test_create_full_scan_success(core_instance):
    """Test successful full scan creation"""
    # Mock the post method to return a successful response
    core_instance.sdk.fullscans.post = lambda files, params: {
        "id": "new-scan-id",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
        "organization_id": "org-123",
        "organization_slug": "test-org",
        "repository_id": "repo-123",
        "committers": ["test@example.com"],
        "repo": "test-repo",
        "branch": "main",
        "commit_message": "test commit",
        "commit_hash": "abc123",
        "pull_request": 1,
        "html_report_url": "https://example.com/report"
    }

    # Mock get_sbom_data to return sample data
    core_instance.get_sbom_data = lambda scan_id: [
        {"id": "pkg-1", "name": "package-1", "version": "1.0.0"},
        {"id": "pkg-2", "name": "package-2", "version": "2.0.0"}
    ]

    # Define test parameters
    files = ["file1", "file2"]
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
    workspace = "test-workspace"

    # Call the method
    result = core_instance.create_full_scan(files, params, workspace)

    # Verify the result
    assert result.id == "new-scan-id"
    assert len(result.sbom_artifacts) == 2
    assert result.sbom_artifacts[0]["name"] == "package-1"
    assert result.sbom_artifacts[1]["name"] == "package-2"

def test_create_full_scan_failure(core_instance):
    """Test full scan creation failure"""
    # Mock the post method to return an error message
    core_instance.sdk.fullscans.post = lambda files, params: "Error creating full scan"

    # Define test parameters
    files = ["file1", "file2"]
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
    workspace = "test-workspace"

    # Call the method
    result = core_instance.create_full_scan(files, params, workspace)

    # Verify the result is an empty FullScan object
    assert hasattr(result, "sbom_artifacts")  # This will exist
    assert result.sbom_artifacts == []  # This should be empty
    assert not hasattr(result, "id")  # This won't exist since no kwargs were passed

def test_get_head_scan_for_repo_success(core_instance):
    """Test successful retrieval of head scan ID for a repository"""
    # Mock the get method to return a successful response
    core_instance.sdk.repos.repo = lambda org_slug, repo_slug: mock.Mock(
        json=lambda: {
            "repository": {
                "id": "repo-123",
                "slug": "test-repo",
                "head_full_scan_id": "head-scan-id",
                "name": "Test Repository",
                "description": "A test repository",
                "homepage": "https://example.com",
                "visibility": "public",
                "archived": False,
                "default_branch": "main"
            }
        }
    )

    # Call the method
    result = core_instance.get_head_scan_for_repo("test-repo")

    # Verify the result
    assert result == "head-scan-id"

def test_get_head_scan_for_repo_not_found(core_instance):
    """Test retrieval of head scan ID for a non-existent repository"""
    # Mock the get method to return an empty response
    core_instance.sdk.repos.repo = lambda org_slug, repo_slug: mock.Mock(
        json=lambda: {}
    )

    # Call the method
    result = core_instance.get_head_scan_for_repo("non-existent-repo")

    # Verify the result is an empty string
    assert result == ""