import json
from pathlib import Path

import pytest

from socketsecurity.core import Core
from socketsecurity.core.classes import Package
from socketsecurity.core.socket_config import SocketConfig


@pytest.fixture
def core(mock_sdk_with_responses):
    config = SocketConfig(api_key="test_key")
    core = Core(config=config, sdk=mock_sdk_with_responses)
    return core

@pytest.fixture
def diff_input() -> tuple[dict[str, Package], dict[str, Package]]:
    """Fixture that loads the saved diff input and converts it to Package objects
    
    Returns:
        Tuple of (added_packages, removed_packages) as Package dictionaries
    """
    test_dir = Path(__file__).parent
    input_file = test_dir / "create_diff_input.json"
    
    with open(input_file) as f:
        data = json.load(f)
    
    # Convert the dictionaries back to Package objects
    added = {k: Package(**v) for k, v in data["added"].items()}
    removed = {k: Package(**v) for k, v in data["removed"].items()}
    
    return added, removed

def test_create_diff_report(core, diff_input):
    """Test creating a diff report"""
    added, removed = diff_input
    
    # Create the diff report
    diff = core.create_diff_report(added, removed)
    


    # Debug what alerts we have
    # print("\nAdded packages alerts:")
    # for pkg_id, pkg in added.items():
    #     print(f"{pkg_id}: {pkg.alerts}")
        
    # print("\nRemoved packages alerts:")
    # for pkg_id, pkg in removed.items():
    #     print(f"{pkg_id}: {pkg.alerts}")
        
    # print("\nFinal new alerts:")
    # for alert in diff.new_alerts:
    #     print(f"{alert.pkg_id}: {alert.type} ({alert.severity})")
    
    # By default direct_only=True, so only direct dependencies should be in new/removed
    assert len(diff.new_packages) == 2  # dp3 and dp4 are direct
    assert len(diff.removed_packages) == 1  # only dp2 is direct
    
    # Verify dp3 Purl object's transformed fields
    dp3_purl = next(p for p in diff.new_packages if p.id == "dp3")
    assert dp3_purl.ecosystem == "pypi"  # Transformed from package.type
    assert dp3_purl.transitives == 3  # Calculated count of transitive deps
    assert dp3_purl.introduced_by == [("direct", "requirements.txt")]  # Generated for direct deps
    
    # Verify dp2 Purl object's transformed fields
    dp2_purl = next(p for p in diff.removed_packages if p.id == "dp2")
    assert dp2_purl.ecosystem == "pypi"
    assert dp2_purl.transitives == 1  # Has one transitive dep (dp2_t1)
    assert dp2_purl.introduced_by == [("direct", "requirements.txt")]

    # Verify specific packages
    new_pkg_ids = {p.id for p in diff.new_packages}
    assert "dp3" in new_pkg_ids  # Direct package
    assert "dp4" in new_pkg_ids  # Direct package
    assert "dp3_t1" not in new_pkg_ids  # Transitive dependency
    
    removed_pkg_ids = {p.id for p in diff.removed_packages}
    assert "dp2" in removed_pkg_ids  # Direct package
    assert "dp2_t1" not in removed_pkg_ids  # Transitive dependency

    # Verify new alerts
    assert len(diff.new_alerts) == 8
    
    alert_details = {
        (alert.type, alert.severity, alert.pkg_id)
        for alert in diff.new_alerts
    }
    
    expected_alerts = {
        ("envVars", "low", "dp3"),
        ("copyleftLicense", "low", "dp3"),
        ("filesystemAccess", "low", "dp3_t1"),
        ("envVars", "low", "dp3_t1"),
        ("envVars", "low", "dp3_t2"),
        ("networkAccess", "middle", "dp3_t2"),
        ("usesEval", "middle", "dp3_t2"),
        ("usesEval", "middle", "dp4"),
    }
    
    assert alert_details == expected_alerts
    
    # Verify new capabilities
    assert "dp3" in diff.new_capabilities
    assert set(diff.new_capabilities["dp3"]) == {"Environment Variables"}

    # Verify capabilities are added to purls
    dp3_purl = next(p for p in diff.new_packages if p.id == "dp3")
    assert hasattr(dp3_purl, "capabilities")
    assert "Environment Variables" in dp3_purl.capabilities

def create_input(core):
    # Get two different scans to compare
    head_scan = core.get_full_scan("head")
    new_scan = core.get_full_scan("new")

    # Get the differences
    added, removed = core.get_added_and_removed_packages(head_scan, new_scan)

    input_to_save = {
        "added": {k: v.to_dict() for k, v in added.items()},
        "removed": {k: v.to_dict() for k, v in removed.items()}
    }

    # Get the directory of the current test file
    test_dir = Path(__file__).parent
    output_file = test_dir / "create_diff_input.json"

    with open(output_file, "w") as f:
        json.dump(input_to_save, f, indent=4)
        
def print_scan_packages(head_scan, new_scan):
    print("\n=== HEAD SCAN PACKAGES ===")
    for pkg_id, pkg in head_scan.packages.items():
        print(f"\nPackage: {pkg_id}")
        pkg_dict = pkg.to_dict()
        pkg_dict.pop('license_text', None)  # Remove license_text from output
        print(json.dumps(pkg_dict, indent=2))

    print("\n=== NEW SCAN PACKAGES ===")
    for pkg_id, pkg in new_scan.packages.items():
        print(f"\nPackage: {pkg_id}")
        pkg_dict = pkg.to_dict()
        pkg_dict.pop('license_text', None)  # Remove license_text from output
        print(json.dumps(pkg_dict, indent=2))

def print_added_and_removed(added, removed):
    print("\n=== ADDED PACKAGES ===")
    for pkg_id, pkg in added.items():
        print(f"\nPackage: {pkg_id}")
        pkg_dict = pkg.to_dict()
        pkg_dict.pop('license_text', None)  # Remove license_text from output
        print(json.dumps(pkg_dict, indent=2))

    print("\n=== REMOVED PACKAGES ===")
    for pkg_id, pkg in removed.items():
        print(f"\nPackage: {pkg_id}")
        pkg_dict = pkg.to_dict()
        pkg_dict.pop('license_text', None)  # Remove license_text from output
        print(json.dumps(pkg_dict, indent=2))

    # def test_create_diff_report_other(core):
    #     """Test creating a diff report from added and removed packages"""
    #     # Setup test package data
    #     added_packages = {
    #         "pkg1": Package(
    #             id="pkg1",
    #             name="package-1",
    #             version="1.0.0",
    #             type="npm",
    #             direct=True,
    #             manifestFiles=[{"file": "package.json"}],
    #             topLevelAncestors=[],
    #             alerts=[
    #                 {
    #                     "key": "fs_access",
    #                     "type": "filesystemAccess",
    #                     "severity": "high",
    #                     "props": {},
    #                     "category": "capability"
    #                 },
    #                 {
    #                     "key": "net_access",
    #                     "type": "networkAccess", 
    #                     "severity": "medium",
    #                     "props": {},
    #                     "category": "capability"
    #                 }
    #             ],
    #             author=["test-author"],
    #             size=1000,
    #             transitives=0,
    #             url="https://socket.dev/npm/package/package-1/overview/1.0.0",
    #             purl="pkg:npm/package-1@1.0.0"
    #         ),
    #         "pkg2": Package(
    #             id="pkg2", 
    #             name="package-2",
    #             version="1.0.0",
    #             type="npm",
    #             direct=False,  # Transitive dependency
    #             manifestFiles=[],
    #             topLevelAncestors=["pkg1"],
    #             alerts=[
    #                 {
    #                     "key": "shell_access",
    #                     "type": "shellAccess",
    #                     "severity": "high",
    #                     "props": {},
    #                     "category": "capability"
    #                 }
    #             ],
    #             author=["other-author"],
    #             size=500,
    #             transitives=0,
    #             url="https://socket.dev/npm/package/package-2/overview/1.0.0",
    #             purl="pkg:npm/package-2@1.0.0"
    #         )
    #     }

    #     removed_packages = {
    #         "old_pkg": Package(
    #             id="old_pkg",
    #             name="old-package",
    #             version="0.9.0",
    #             type="npm",
    #             direct=True,
    #             manifestFiles=[{"file": "package.json"}],
    #             topLevelAncestors=[],
    #             alerts=[
    #                 {
    #                     "key": "fs_access",  # Same alert type as pkg1
    #                     "type": "filesystemAccess",
    #                     "severity": "high",
    #                     "props": {},
    #                     "category": "capability"
    #                 }
    #             ],
    #             author=["old-author"],
    #             size=800,
    #             transitives=0,
    #             url="https://socket.dev/npm/package/old-package/overview/0.9.0",
    #             purl="pkg:npm/old-package@0.9.0"
    #         )
    #     }

    #     # Create diff report
    #     diff = core.create_diff_report(added_packages, removed_packages)

    #     # Verify new packages (should only include direct dependencies)
    #     assert len(diff.new_packages) == 1
    #     new_pkg = diff.new_packages[0]
    #     assert new_pkg.id == "pkg1"
    #     assert new_pkg.name == "package-1"
    #     assert new_pkg.version == "1.0.0"
    #     assert new_pkg.direct is True

    #     # Verify removed packages (should only include direct dependencies)
    #     assert len(diff.removed_packages) == 1
    #     removed_pkg = diff.removed_packages[0]
    #     assert removed_pkg.id == "old_pkg"
    #     assert removed_pkg.name == "old-package"
    #     assert removed_pkg.version == "0.9.0"

    #     # Verify new alerts (should include alerts from both direct and transitive deps)
    #     assert len(diff.new_alerts) > 0
    #     alert_types = {alert.type for alert in diff.new_alerts}
    #     assert "networkAccess" in alert_types  # New alert type
    #     assert "shellAccess" in alert_types   # New alert type
    #     # filesystemAccess should not be in new alerts since it existed in removed packages

    #     # Verify new capabilities
    #     assert "pkg1" in diff.new_capabilities
    #     assert set(diff.new_capabilities["pkg1"]) == {"File System Access", "Network Access"}
    #     assert "pkg2" in diff.new_capabilities
    #     assert set(diff.new_capabilities["pkg2"]) == {"Shell Access"}

    #     # Verify capabilities are added to purls
    #     pkg1_purl = next(p for p in diff.new_packages if p.id == "pkg1")
    #     assert hasattr(pkg1_purl, "capabilities")
    #     assert set(pkg1_purl.capabilities) == {"File System Access", "Network Access"}