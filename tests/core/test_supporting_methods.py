from socketsecurity.core import Core
from socketsecurity.core.classes import Diff, Issue, Package, Purl


def test_create_purl():
    """Test creating a PURL from package data"""
    # Setup test package data
    pkg_type = "npm"
    pkg_name = "test-package"
    pkg_version = "1.0.0"
    
    packages = {
        "test_pkg": Package(
            id="test_pkg",
            name=pkg_name,
            version=pkg_version,
            type=pkg_type,
            direct=True,
            manifestFiles=[{"file": "package.json"}],
            topLevelAncestors=[],
            author=["test-author"],
            size=1000,
            transitives=0,
            purl=f"pkg:{pkg_type}/{pkg_name}@{pkg_version}"
        )
    }
    
    # Create PURL
    purl = Core.create_purl("test_pkg", packages)
    
    # Verify PURL properties
    assert purl.id == "test_pkg"
    assert purl.name == pkg_name
    assert purl.version == pkg_version
    assert purl.ecosystem == pkg_type
    assert purl.direct is True
    assert purl.introduced_by == [("direct", "package.json")]
    assert purl.author == ["test-author"]
    assert purl.size == 1000
    assert purl.transitives == 0
    assert purl.url == f"https://socket.dev/{pkg_type}/package/{pkg_name}/overview/{pkg_version}"
    assert purl.purl == f"pkg:{pkg_type}/{pkg_name}@{pkg_version}" 


def test_get_source_data():
    """Test getting source data for direct and transitive dependencies"""
    # Setup test package data
    direct_pkg = Package(
        id="direct_pkg",
        name="direct-package",
        version="1.0.0",
        type="npm",
        direct=True,
        manifestFiles=[
            {"file": "package.json", "start": 10, "end": 20}
        ],
        topLevelAncestors=[],
        author=["test-author"],
        size=1000,
        transitives=1
    )
    
    transitive_pkg = Package(
        id="t_pkg",
        name="transitive-package",
        version="2.0.0",
        type="npm",
        direct=False,
        manifestFiles=[],
        topLevelAncestors=["direct_pkg"],
        author=["other-author"],
        size=500,
        transitives=0
    )
    
    packages = {
        "direct_pkg": direct_pkg,
        "t_pkg": transitive_pkg
    }
    
    # Test direct package
    direct_source = Core.get_source_data(direct_pkg, packages)
    assert direct_source == [("direct", "package.json")]
    
    # Test transitive package
    trans_source = Core.get_source_data(transitive_pkg, packages)
    assert trans_source == [("npm/direct-package@1.0.0", "package.json")] 


def test_get_capabilities_for_added_packages():
    """Test mapping package alerts to capabilities"""
    # Setup test packages with various alert types
    packages = {
        "pkg1": Package(
            id="pkg1",
            name="package-1",
            version="1.0.0",
            type="npm",
            direct=True,
            manifestFiles=[{"file": "package.json"}],
            topLevelAncestors=[],
            alerts=[
                {
                    "key": "alert1",
                    "type": "filesystemAccess",
                    "severity": "low",
                    "category": "supplyChainRisk",
                    "file": "index.js"
                },
                {
                    "key": "alert2",
                    "type": "networkAccess",
                    "severity": "middle",
                    "category": "supplyChainRisk",
                    "file": "lib.js"
                }
            ]
        ),
        "pkg2": Package(
            id="pkg2",
            name="package-2",
            version="2.0.0",
            type="npm",
            direct=True,
            manifestFiles=[{"file": "package.json"}],
            topLevelAncestors=[],
            alerts=[
                {
                    "key": "alert3",
                    "type": "usesEval",
                    "severity": "high",
                    "category": "supplyChainRisk",
                    "file": "main.js"
                }
            ]
        )
    }
    
    # Get capabilities for these packages
    capabilities = Core.get_capabilities_for_added_packages(packages)
    
    # Verify the returned dictionary structure
    assert "pkg1" in capabilities
    assert "pkg2" in capabilities
    
    # Verify capabilities for pkg1 (has both filesystem and network access)
    assert "File System Access" in capabilities["pkg1"]
    assert "Network Access" in capabilities["pkg1"]
    assert len(capabilities["pkg1"]) == 2
    
    # Verify capabilities for pkg2 (has eval)
    assert "Uses Eval" in capabilities["pkg2"]
    assert len(capabilities["pkg2"]) == 1 


def test_get_new_alerts():
    """Test finding new alerts between added and removed packages"""
    # Setup test data
    added_alerts = {
        "key1": [  # Completely new alert type
            Issue(
                pkg_type="npm",
                pkg_name="pkg1",
                pkg_version="1.0.0",
                pkg_id="pkg1",
                key="key1",
                type="filesystemAccess",
                severity="high",
                error=True,
                purl="pkg:npm/pkg1@1.0.0",
                manifests="package.json"
            )
        ],
        "key2": [  # Existing alert type but new instance
            Issue(
                pkg_type="npm",
                pkg_name="pkg2",
                pkg_version="1.0.0",
                pkg_id="pkg2",
                key="key2",
                type="networkAccess",
                severity="medium",
                warn=True,
                purl="pkg:npm/pkg2@1.0.0",
                manifests="package.json"
            )
        ],
        "key3": [  # Alert that should be ignored (no error/warn)
            Issue(
                pkg_type="npm",
                pkg_name="pkg3",
                pkg_version="1.0.0",
                pkg_id="pkg3",
                key="key3",
                type="info",
                severity="low",
                monitor=True,
                purl="pkg:npm/pkg3@1.0.0",
                manifests="package.json"
            )
        ]
    }
    
    removed_alerts = {
        "key2": [  # Existing alert with different package
            Issue(
                pkg_type="npm",
                pkg_name="old-pkg",
                pkg_version="0.9.0",
                pkg_id="old-pkg",
                key="key2",
                type="networkAccess",
                severity="medium",
                warn=True,
                purl="pkg:npm/old-pkg@0.9.0",
                manifests="package.json"
            )
        ]
    }
    
    # Test with ignore_readded=True (default)
    new_alerts = Core.get_new_alerts(added_alerts, removed_alerts)
    
    # Verify results
    assert len(new_alerts) == 2  # Should only include key1 and key2 alerts
    
    # Verify the completely new alert (key1) is included
    key1_alerts = [a for a in new_alerts if a.key == "key1"]
    assert len(key1_alerts) == 1
    assert key1_alerts[0].type == "filesystemAccess"
    assert key1_alerts[0].error is True
    
    # Verify the new instance of existing alert (key2) is included
    key2_alerts = [a for a in new_alerts if a.key == "key2"]
    assert len(key2_alerts) == 1
    assert key2_alerts[0].type == "networkAccess"
    assert key2_alerts[0].warn is True
    
    # Verify the monitor-only alert (key3) is not included
    key3_alerts = [a for a in new_alerts if a.key == "key3"]
    assert len(key3_alerts) == 0
    
    # Test with ignore_readded=False
    all_alerts = Core.get_new_alerts(added_alerts, removed_alerts, ignore_readded=False)
    assert len(all_alerts) == 2  # Should still be 2 since key3 is still monitor-only 


def test_add_purl_capabilities():
    """Test adding capabilities to purls in a diff"""
    # Setup test data
    diff = Diff(
        id="test_diff",
        new_packages=[
            Purl(
                id="pkg1",
                name="package-1",
                version="1.0.0",
                ecosystem="npm",
                direct=True,
                introduced_by=[("direct", "package.json")],
                author=["test-author"],
                size=1000,
                transitives=0,
                url="https://socket.dev/npm/package/package-1/overview/1.0.0",
                purl="pkg:npm/package-1@1.0.0"
            ),
            Purl(
                id="pkg2",
                name="package-2",
                version="2.0.0",
                ecosystem="npm",
                direct=True,
                introduced_by=[("direct", "package.json")],
                author=["other-author"],
                size=500,
                transitives=0,
                url="https://socket.dev/npm/package/package-2/overview/2.0.0",
                purl="pkg:npm/package-2@2.0.0"
            )
        ],
        new_capabilities={
            "pkg1": ["File System Access", "Network Access"],
            # pkg2 intentionally has no capabilities
        }
    )
    
    # Add capabilities to purls
    Core.add_purl_capabilities(diff)
    
    # Verify results
    assert len(diff.new_packages) == 2
    
    # Check package with capabilities
    pkg1 = next(p for p in diff.new_packages if p.id == "pkg1")
    assert hasattr(pkg1, "capabilities")
    assert pkg1.capabilities == ["File System Access", "Network Access"]
    
    # Check package without capabilities
    pkg2 = next(p for p in diff.new_packages if p.id == "pkg2")
    assert pkg2.capabilities == []
