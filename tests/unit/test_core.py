from unittest.mock import MagicMock, mock_open, patch

import pytest

from socketsecurity.core import Core
from socketsecurity.core.classes import Diff, Issue, Package, Purl


@pytest.fixture
def sample_package():
    return Package(
        id="pkg1",
        name="test-package",
        version="1.0.0",
        type="npm",
        direct=True,
        manifestFiles=[{"file": "package.json"}],
        alerts=[],
        author=["Test Author"],
        size=1000,
        url="https://example.com",
        purl="pkg:npm/test-package@1.0.0"
    )


def test_save_file():
    """Test file saving functionality"""
    with patch('builtins.open', mock_open()) as mock_file:
        Core.save_file("test.txt", "test content")
        mock_file.assert_called_once_with("test.txt", "w")
        mock_file().write.assert_called_once_with("test content")

def test_get_manifest_files():
    """Test manifest file handling for all branches"""
    # Branch 1: Direct package with single manifest
    direct_pkg_single = Package(
        id="pkg1",
        name="test-package",
        version="1.0.0",
        type="npm",
        direct=True,
        manifestFiles=[{"file": "package.json"}],
        alerts=[]
    )
    packages = {"pkg1": direct_pkg_single}
    result = Core.get_manifest_files(direct_pkg_single, packages)
    assert result == "package.json"

    # Branch 2: Direct package with multiple manifests
    direct_pkg_multiple = Package(
        id="pkg2",
        name="test-package",
        version="1.0.0",
        type="npm",
        direct=True,
        manifestFiles=[
            {"file": "package.json"},
            {"file": "package-lock.json"}
        ],
        alerts=[]
    )
    packages["pkg2"] = direct_pkg_multiple
    result = Core.get_manifest_files(direct_pkg_multiple, packages)
    assert result == "package.json;package-lock.json"

    # Branch 3: Transitive package with single top-level ancestor
    transitive_single = Package(
        id="pkg3",
        name="transitive-pkg",
        version="1.0.0",
        type="npm",
        direct=False,
        topLevelAncestors=["pkg1"],
        manifestFiles=[],
        alerts=[]
    )
    packages["pkg3"] = transitive_single
    result = Core.get_manifest_files(transitive_single, packages)
    assert result == "transitive-pkg@1.0.0(package.json)"

    # Branch 4: Transitive package with multiple top-level ancestors
    transitive_multiple = Package(
        id="pkg4",
        name="transitive-pkg",
        version="1.0.0",
        type="npm",
        direct=False,
        topLevelAncestors=["pkg2"],
        manifestFiles=[],
        alerts=[]
    )
    packages["pkg4"] = transitive_multiple
    result = Core.get_manifest_files(transitive_multiple, packages)
    assert result == "transitive-pkg@1.0.0(package.json);transitive-pkg@1.0.0(package-lock.json)"

def test_create_sbom_dict_all_branches():
    """Test SBOM dictionary creation covering all conditional branches"""
    sbom_data = [
        {   # Top-level package with transitives
            "id": "pkg1",
            "name": "root-pkg",
            "version": "1.0.0",
            "type": "npm",
            "direct": True,
            "manifestFiles": [{"file": "package.json"}],
            "alerts": [],
            "topLevelAncestors": []
        },
        {   # First transitive
            "id": "pkg2",
            "name": "dep-pkg",
            "version": "2.0.0",
            "type": "npm",
            "direct": False,
            "manifestFiles": [],
            "alerts": [],
            "topLevelAncestors": ["pkg1"]
        },
        {   # Second transitive for same top-level
            "id": "pkg3",
            "name": "another-dep",
            "version": "1.0.0",
            "type": "npm",
            "direct": False,
            "manifestFiles": [],
            "alerts": [],
            "topLevelAncestors": ["pkg1"]
        },
        {   # Duplicate package (same ID as pkg1)
            "id": "pkg1",
            "name": "root-pkg",
            "version": "1.0.0",
            "type": "npm",
            "direct": True,
            "manifestFiles": [{"file": "package.json"}],
            "alerts": [],
            "topLevelAncestors": []
        },
        {   # Package with no transitives
            "id": "pkg4",
            "name": "standalone",
            "version": "1.0.0",
            "type": "npm",
            "direct": True,
            "manifestFiles": [{"file": "package.json"}],
            "alerts": [],
            "topLevelAncestors": []
        }
    ]

    with patch('builtins.print') as mock_print:
        result = Core.create_sbom_dict(sbom_data)

    mock_print.assert_called_once_with("Duplicate package?")
    assert len(result) == 4

    # Verify transitive counting
    assert result["pkg1"].transitives == 2  # Two transitive dependencies
    assert result["pkg4"].transitives == 0  # No transitives, but property exists

    # Verify all packages present
    assert all(pkg_id in result for pkg_id in ["pkg1", "pkg2", "pkg3", "pkg4"])

def test_check_alert_capabilities():
    """Test all branches of alert capability checking"""
    package = Package(
        id="pkg1",
        name="test-pkg",
        version="1.0.0",
        type="npm",
        direct=True,
        alerts=[
            {"type": "envVars"},
            {"type": "networkAccess"},
            {"type": "unsupportedType"},  # Should be ignored
            {"type": "shellAccess"}  # Will be duplicate in capabilities
        ]
    )

    # Test new package (no head_package)
    capabilities = {}
    result = Core.check_alert_capabilities(package, capabilities, "pkg1")
    assert "pkg1" in result
    assert set(result["pkg1"]) == {"Environment", "Network", "Shell"}

    # Test with existing capabilities
    capabilities = {"pkg1": ["Shell"]}  # Existing capability
    result = Core.check_alert_capabilities(package, capabilities, "pkg1")
    assert len(result["pkg1"]) == 3
    assert "Shell" in result["pkg1"]  # Existing capability
    assert "Environment" in result["pkg1"]  # New capability
    assert "Network" in result["pkg1"]  # New capability

    # Test with head_package having some matching alerts
    head_package = Package(
        id="pkg1",
        name="test-pkg",
        version="1.0.0",
        type="npm",
        direct=True,
        alerts=[
            {"type": "envVars"},  # Should be skipped as existing
            {"type": "filesystemAccess"}  # Different alert
        ]
    )

    capabilities = {}
    result = Core.check_alert_capabilities(package, capabilities, "pkg1", head_package)
    assert "pkg1" in result
    assert "Environment" not in result["pkg1"]  # Should be skipped
    assert "Network" in result["pkg1"]  # Should be included
    assert "File System" not in result["pkg1"]  # Not in new package

def test_add_capabilities_to_purl():
    """Test adding capabilities to PURLs in a diff"""
    diff = Diff()

    # Create PURLs with and without capabilities
    purl1 = Purl(
        id="pkg1",
        name="test-pkg",
        version="1.0.0",
        ecosystem="npm",
        direct=True,
        introduced_by=[("direct", "package.json")],
        author=["Test Author"],
        size=1000,
        url="https://example.com",
        purl="pkg:npm/test-pkg@1.0.0"
    )
    purl2 = Purl(
        id="pkg2",
        name="other-pkg",
        version="2.0.0",
        ecosystem="npm",
        direct=True,
        introduced_by=[("direct", "package.json")],
        author=["Other Author"],
        size=2000,
        url="https://example.com/other",
        purl="pkg:npm/other-pkg@2.0.0"
    )

    diff.new_packages = [purl1, purl2]
    diff.new_capabilities = {
        "pkg1": ["Network", "Shell"],  # Has capabilities
        # pkg2 intentionally missing from capabilities
    }

    result = Core.add_capabilities_to_purl(diff)

    # Verify purl1 got its capabilities
    assert result.new_packages[0].capabilities == ["Network", "Shell"]

    # Verify purl2 has empty capabilities
    assert result.new_packages[1].capabilities == {}

    # Verify both PURLs are still present
    assert len(result.new_packages) == 2

def test_compare_capabilities():
    """Test comparison of capabilities between package sets"""
    # Create test packages
    new_pkg1 = Package(
        id="pkg1",
        name="test-pkg",
        version="1.0.0",
        type="npm",
        direct=True,
        alerts=[
            {"type": "envVars"},
            {"type": "networkAccess"}
        ]
    )

    new_pkg2 = Package(
        id="pkg2",
        name="other-pkg",
        version="2.0.0",
        type="npm",
        direct=True,
        alerts=[
            {"type": "shellAccess"}
        ]
    )

    head_pkg1 = Package(
        id="pkg1",
        name="test-pkg",
        version="1.0.0",
        type="npm",
        direct=True,
        alerts=[
            {"type": "envVars"}  # Only environment vars in head
        ]
    )

    # Test cases:
    # 1. Package exists in head with some matching alerts
    # 2. Package exists in head with no matching alerts
    # 3. Package doesn't exist in head

    new_packages = {
        "pkg1": new_pkg1,
        "pkg2": new_pkg2
    }

    head_packages = {
        "pkg1": head_pkg1
    }

    result = Core.compare_capabilities(new_packages, head_packages)

    # Verify pkg1 only shows new capability
    assert "Environment" not in result["pkg1"]  # Exists in head
    assert "Network" in result["pkg1"]  # New in current

    # Verify pkg2 shows all capabilities (not in head)
    assert "Shell" in result["pkg2"]

    # Verify no unexpected capabilities
    assert len(result["pkg1"]) == 1
    assert len(result["pkg2"]) == 1

def test_get_source_data():
    """Test source data generation for direct and transitive packages"""
    # Test Case 1: Direct package with single manifest
    direct_pkg = Package(
        id="pkg1",
        name="test-package",
        version="1.0.0",
        type="npm",
        direct=True,
        manifestFiles=[{"file": "package.json"}],
        alerts=[]
    )
    packages = {"pkg1": direct_pkg}
    result = Core.get_source_data(direct_pkg, packages)
    assert result == [("direct", "package.json")]

    # Test Case 2: Direct package with multiple manifests
    direct_multi = Package(
        id="pkg2",
        name="test-package",
        version="1.0.0",
        type="npm",
        direct=True,
        manifestFiles=[
            {"file": "package.json"},
            {"file": "package-lock.json"}
        ],
        alerts=[]
    )
    packages["pkg2"] = direct_multi
    result = Core.get_source_data(direct_multi, packages)
    assert result == [("direct", "package.json;package-lock.json")]

    # Test Case 3: Transitive package with single top-level ancestor
    top_pkg = Package(
        id="top1",
        name="top-package",
        version="1.0.0",
        type="npm",
        direct=True,
        manifestFiles=[{"file": "package.json"}],
        alerts=[]
    )
    transitive = Package(
        id="trans1",
        name="trans-package",
        version="2.0.0",
        type="npm",
        direct=False,
        topLevelAncestors=["top1"],
        manifestFiles=[],
        alerts=[]
    )
    packages.update({
        "top1": top_pkg,
        "trans1": transitive
    })
    result = Core.get_source_data(transitive, packages)
    assert result == [("npm/top-package@1.0.0", "package.json")]

    # Test Case 4: Transitive package with multiple top-level ancestors
    top_pkg2 = Package(
        id="top2",
        name="top-package-2",
        version="3.0.0",
        type="npm",
        direct=True,
        manifestFiles=[{"file": "other-package.json"}],
        alerts=[]
    )
    transitive_multi = Package(
        id="trans2",
        name="trans-package-2",
        version="4.0.0",
        type="npm",
        direct=False,
        topLevelAncestors=["top1", "top2"],
        manifestFiles=[],
        alerts=[]
    )
    packages.update({
        "top2": top_pkg2,
        "trans2": transitive_multi
    })
    result = Core.get_source_data(transitive_multi, packages)
    assert result == [
        ("npm/top-package@1.0.0", "package.json"),
        ("npm/top-package-2@3.0.0", "other-package.json")
    ]

def test_create_purl():
    """Test PURL creation with all required fields"""
    # Test Case 1: Direct package with provided PURL
    direct_pkg = Package(
        id="pkg1",
        name="test-package",
        version="1.0.0",
        type="npm",
        direct=True,
        manifestFiles=[{"file": "package.json"}],
        alerts=[],
        author=["Test Author"],
        size=1000,
        transitives=0,
        url="https://socket.dev/npm/package/test-package/overview/1.0.0",
        purl="pkg:npm/test-package@1.0.0"  # Explicitly provided PURL
    )
    packages = {"pkg1": direct_pkg}
    purl, package = Core.create_purl("pkg1", packages)

    # Verify PURL format is preserved
    assert purl.purl == "pkg:npm/test-package@1.0.0"

    # Test Case 2: Package without provided PURL (should be generated)
    no_purl_pkg = Package(
        id="pkg2",
        name="auto-package",
        version="2.0.0",
        type="npm",
        direct=True,
        manifestFiles=[{"file": "package.json"}],
        alerts=[],
        author=["Test Author"],
        size=1000,
        transitives=0,
        url="https://socket.dev/npm/package/auto-package/overview/2.0.0"
        # No purl provided - should be auto-generated
    )
    packages["pkg2"] = no_purl_pkg
    purl, package = Core.create_purl("pkg2", packages)

    # Verify auto-generated PURL has correct format
    assert purl.purl == "pkg:npm/auto-package@2.0.0"

    # Rest of existing test cases...

def test_find_files():
    """Test file discovery with glob patterns"""
    time_calls = []  # Track time.time() calls

    def mock_time():
        val = len(time_calls)
        time_calls.append(val)
        return val

    with patch('socketsecurity.core.glob') as mock_glob, \
         patch('socketsecurity.core.log') as mock_log, \
         patch('time.time', side_effect=mock_time):

        # Mock glob to return different files for different patterns
        def mock_glob_side_effect(pattern, recursive=True):
            if "package.json" in pattern:
                return [
                    "/path/to/package.json",
                    "/path/to/nested/package.json",
                    "C:/path/with/windows/style/package.json"  # This is actually a unique path
                ]
            elif "requirements.txt" in pattern:
                return [
                    "/path/to/requirements.txt",
                    "/path/to/requirements.txt"  # Duplicate that will be removed
                ]
            elif "go.mod" in pattern:
                return ["/path/to/go.mod"]
            return []

        mock_glob.side_effect = mock_glob_side_effect

        # Test file discovery
        result = Core.find_files("/path/to")

        # Print debug info for verification
        print(f"Total time.time() calls: {len(time_calls)}")
        print("Found files:", result)

        # Verify results contain all unique files (5 total)
        assert len(result) == 5  # Updated to expect 5 unique files
        assert "/path/to/package.json" in result
        assert "/path/to/nested/package.json" in result
        assert "/path/to/requirements.txt" in result
        assert "/path/to/go.mod" in result
        assert "C:/path/with/windows/style/package.json" in result  # Windows path is unique

        # Verify glob was called with correct patterns
        glob_patterns = [call[0][0] for call in mock_glob.call_args_list]
        assert any("package.json" in pattern for pattern in glob_patterns)
        assert any("requirements.txt" in pattern for pattern in glob_patterns)
        assert any("go.mod" in pattern for pattern in glob_patterns)

        # Verify logging with actual number of time calls
        mock_log.debug.assert_any_call("Starting Find Files")
        mock_log.debug.assert_any_call("Finished Find Files")
        final_time = len(time_calls) - 1
        mock_log.info.assert_called_with(f"Found 5 in {final_time:.2f} seconds")

def test_create_purl_edge_cases():
    """Test PURL creation with edge cases"""
    # Test with missing optional fields
    minimal_pkg = Package(
        id="pkg1",
        name="test-pkg",
        version="1.0.0",
        type="npm",
        direct=True,
        manifestFiles=[{"file": "package.json"}],
        alerts=[]
        # Missing: author, size, transitives, url, purl
    )
    packages = {"pkg1": minimal_pkg}
    purl, package = Core.create_purl("pkg1", packages)

    # Verify defaults for missing fields
    assert purl.author == []  # Should default to empty list
    assert purl.size == 0  # Should default to 0
    assert purl.transitives == 0  # Should default to 0
    assert purl.url == "https://socket.dev/npm/package/test-pkg/overview/1.0.0"  # URL is auto-generated for all packages
    assert purl.purl == "pkg:npm/test-pkg@1.0.0"  # Should generate purl

    # Test with different package type
    pip_pkg = Package(
        id="pkg2",
        name="test-pkg",
        version="1.0.0",
        type="pip",  # Different package type
        direct=True,
        manifestFiles=[{"file": "requirements.txt"}],
        alerts=[]
    )
    packages = {"pkg2": pip_pkg}
    purl, package = Core.create_purl("pkg2", packages)
    assert purl.url == "https://socket.dev/pip/package/test-pkg/overview/1.0.0"  # URL is auto-generated with pip type
    assert purl.purl == "pkg:pip/test-pkg@1.0.0"  # Should generate purl with pip type

def test_get_license_details():
    """Test license details handling with mocked Licenses"""
    with patch('socketsecurity.core.Licenses') as MockLicenses:
        # Setup mock license object with licenseText property
        mock_license = type('MockLicense', (), {'licenseText': 'Mock License Text'})()

        # Configure the mock Licenses class
        mock_licenses_instance = MagicMock()
        mock_licenses_instance.MIT = mock_license
        MockLicenses.return_value = mock_licenses_instance

        # Test package with valid license
        package = Package(
            id="pkg1",
            name="test-pkg",
            version="1.0.0",
            type="npm",
            direct=True,
            license="MIT",
            manifestFiles=[],
            alerts=[]
        )

        # First test: valid license
        MockLicenses.make_python_safe = MagicMock(return_value="MIT")
        result = Core.get_license_details(package)
        assert result.license_text == "Mock License Text"

        # Second test: unknown license
        package = Package(  # Create fresh package without license_text
            id="pkg1",
            name="test-pkg",
            version="1.0.0",
            type="npm",
            direct=True,
            license="Unknown-License",
            manifestFiles=[],
            alerts=[]
        )
        MockLicenses.make_python_safe = MagicMock(return_value=None)
        mock_licenses_instance = MagicMock(spec=[])  # Empty spec means no attributes
        MockLicenses.return_value = mock_licenses_instance

        result = Core.get_license_details(package)
        assert result.license_text == ""  # Check for empty string instead of missing attribute

def test_compare_issue_alerts():
    """Test comparison of issue alerts between scans, covering all branches"""

    def create_issue(key, error=False, warn=False, purl="pkg:npm/test@1.0.0", type="security"):
        return Issue(
            key=key,
            type=type,
            severity="high",
            description="Test desc",
            title="Test title",
            purl=purl,
            manifests="package.json",
            error=error,
            warn=warn
        )

    # Branch 1: alert_key not in head_scan_alerts
    issue_error = create_issue("key1", error=True, purl="pkg:npm/test1@1.0.0")
    issue_warn = create_issue("key2", warn=True, purl="pkg:npm/test2@1.0.0")
    issue_no_alert = create_issue("key3", purl="pkg:npm/test3@1.0.0")  # Neither error nor warn

    new_alerts = {
        "key1": [issue_error],
        "key2": [issue_warn],
        "key3": [issue_no_alert]
    }
    head_alerts = {}
    result = Core.compare_issue_alerts(new_alerts, head_alerts, [])
    assert len(result) == 2  # Only error and warn issues should be included
    assert {i.key for i in result} == {"key1", "key2"}
    assert {i.purl for i in result} == {"pkg:npm/test1@1.0.0", "pkg:npm/test2@1.0.0"}

    # Branch 1a: Duplicate consolidated alerts (same purl/manifests/type)
    duplicate_issue = create_issue(
        "key4",
        error=True,
        purl=issue_error.purl,
        type=issue_error.type
    )
    new_alerts = {
        "key1": [issue_error],
        "key4": [duplicate_issue]
    }
    result = Core.compare_issue_alerts(new_alerts, head_alerts, [])
    assert len(result) == 1  # Duplicate should be consolidated
    assert result[0].purl == issue_error.purl

    # Branch 2: alert_key exists in head_scan_alerts but with different purl
    new_issue = create_issue("key5", error=True, purl="pkg:npm/new@1.0.0")
    head_issue = create_issue("key5", error=True, purl="pkg:npm/old@1.0.0")

    new_alerts = {"key5": [new_issue]}
    head_alerts = {"key5": [head_issue]}
    result = Core.compare_issue_alerts(new_alerts, head_alerts, [])
    assert len(result) == 1  # Different purl should be treated as new alert
    assert result[0].purl == "pkg:npm/new@1.0.0"

    # Branch 2a & 2b: Multiple alerts with mixed conditions
    new_alerts = {
        "key6": [
            create_issue("key6", error=True, purl="pkg:npm/test1@1.0.0"),  # New error
            create_issue("key6", warn=True, purl="pkg:npm/test2@1.0.0"),   # New warning
            create_issue("key6", purl="pkg:npm/test3@1.0.0"),              # No error/warn
            create_issue("key6", error=True, purl="pkg:npm/test4@1.0.0")   # Will be in head
        ]
    }
    head_alerts = {
        "key6": [
            create_issue("key6", error=True, purl="pkg:npm/test4@1.0.0")   # Existing in head
        ]
    }
    result = Core.compare_issue_alerts(new_alerts, head_alerts, [])
    assert len(result) == 2  # Should only include new error and warning alerts
    assert {i.purl for i in result} == {"pkg:npm/test1@1.0.0", "pkg:npm/test2@1.0.0"}
