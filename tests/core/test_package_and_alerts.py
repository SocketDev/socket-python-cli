from dataclasses import dataclass
from unittest.mock import Mock

import pytest
from socketdev import socketdev

from socketsecurity.core import Core
from socketsecurity.core.classes import Issue, Package
from socketsecurity.core.socket_config import SocketConfig


@dataclass
class MockArtifact:
    id: str
    name: str
    version: str
    type: str
    release: str
    diffType: str
    license: str
    score: dict
    alerts: list
    direct: bool
    topLevelAncestors: list


class TestPackageAndAlerts:
    @staticmethod
    def make_package(**overrides):
        base = dict(
            id="pkg:npm/test@1.0.0",
            name="test",
            version="1.0.0",
            type="npm",
            release="tar-gz",
            diffType="added",
            score={},
            alerts=[],
            topLevelAncestors=[],
        )
        base.update(overrides)
        return Package(**base)

    @pytest.fixture
    def mock_sdk(self):
        mock = Mock(spec=socketdev)
        # Set up org.get() to return expected data
        mock.org = Mock()
        mock.org.get = Mock(return_value={
            "organizations": {
                "test-org-id": {
                    "slug": "test-org"
                }
            }
        })
        
        # Set up settings.get() to return empty response
        mock.settings = Mock()
        settings_response = Mock()
        settings_response.success = True
        mock.settings.get = Mock(return_value=settings_response)

        # Set up licensemetadata.post() used by create_packages_dict()
        mock.licensemetadata = Mock()
        mock.licensemetadata.post = Mock(return_value=[{"text": ""}])
        
        return mock
    
    @pytest.fixture
    def config(self):
        config = SocketConfig(
            api_key="test-key",
            allow_unverified_ssl=False
        )
        return config
    
    @pytest.fixture
    def core(self, mock_sdk, config):
        return Core(config=config, sdk=mock_sdk)

    def test_create_packages_dict_basic(self, core):
        """Test basic package dictionary creation with no transitives"""
        mock_artifacts = [
            MockArtifact(
                id="pkg:npm/test@1.0.0",
                name="test",
                version="1.0.0",
                type="npm",
                release="tar-gz",
                diffType="added",
                license="MIT",
                score={},
                alerts=[],
                direct=True,
                topLevelAncestors=[]
            )
        ]
        
        packages = core.create_packages_dict(mock_artifacts)
        
        assert len(packages) == 1
        pkg = packages["pkg:npm/test@1.0.0"]
        assert pkg.name == "test"
        assert pkg.version == "1.0.0"
        assert pkg.transitives == 0

    def test_create_packages_dict_with_transitives(self, core):
        """Test package dictionary creation with transitive dependencies"""
        mock_artifacts = [
            MockArtifact(
                id="pkg:npm/parent@1.0.0",
                name="parent",
                version="1.0.0",
                type="npm",
                release="tar-gz",
                diffType="added",
                license="MIT",
                score={},
                alerts=[],
                direct=True,
                topLevelAncestors=[]
            ),
            MockArtifact(
                id="pkg:npm/child@1.0.0",
                name="child",
                version="1.0.0",
                type="npm",
                release="tar-gz",
                diffType="added",
                license="MIT",
                score={},
                alerts=[],
                direct=False,
                topLevelAncestors=["pkg:npm/parent@1.0.0"]
            )
        ]
        
        packages = core.create_packages_dict(mock_artifacts)
        
        assert len(packages) == 2
        parent = packages["pkg:npm/parent@1.0.0"]
        child = packages["pkg:npm/child@1.0.0"]
        assert parent.transitives == 1
        assert not child.direct
        assert child.topLevelAncestors == ["pkg:npm/parent@1.0.0"]

    def test_add_package_alerts_basic(self, core):
        """Test adding basic alerts to collection"""
        package = self.make_package(
            alerts=[{
                "type": "networkAccess",
                "key": "test-alert",
                "severity": "high"
            }],
            topLevelAncestors=[]
        )
        
        alerts_collection = {}
        packages = {package.id: package}
        
        result = core.add_package_alerts_to_collection(package, alerts_collection, packages)
        
        assert len(result) == 1
        assert "test-alert" in result
        alert = result["test-alert"][0]
        assert alert.type == "networkAccess"
        assert alert.severity == "high"



    def test_get_capabilities_for_added_packages(self, core):
        """Test capability extraction from package alerts"""
        added_packages = {
            "pkg:npm/test@1.0.0": self.make_package(
                alerts=[{
                    "type": "networkAccess",
                    "key": "test-alert"
                }],
            )
        }
        
        capabilities = Core.get_capabilities_for_added_packages(added_packages)
        
        assert len(capabilities) == 1
        assert "pkg:npm/test@1.0.0" in capabilities
        assert "Network Access" in capabilities["pkg:npm/test@1.0.0"]

    def test_get_new_alerts_basic(self):
        """Test identification of new alerts"""
        added_alerts = {
            "test-alert": [Issue(
                key="test-alert",
                type="networkAccess",
                error=True,
                pkg_type="npm",
                pkg_name="test-package",
                pkg_version="1.0.0",
                purl="pkg:npm/test-package@1.0.0",
                manifests=""  # Required by get_new_alerts
            )]
        }
        removed_alerts = {}
        
        new_alerts = Core.get_new_alerts(added_alerts, removed_alerts)
        
        assert len(new_alerts) == 1
        assert new_alerts[0].key == "test-alert"
        assert new_alerts[0].error is True

    def test_get_new_alerts_with_readded(self):
        """Test handling of alerts that were removed and readded"""
        alert = Issue(
            key="test-alert",
            type="networkAccess",
            error=True,
            pkg_type="npm",
            pkg_name="test-package",
            pkg_version="1.0.0",
            purl="pkg:npm/test-package@1.0.0",
            manifests=""  # Required by get_new_alerts
        )
        added_alerts = {"test-alert": [alert]}
        removed_alerts = {"test-alert": [alert]}
        
        # With ignore_readded=True (default)
        new_alerts = Core.get_new_alerts(added_alerts, removed_alerts)
        assert len(new_alerts) == 0
        
        # With ignore_readded=False
        new_alerts = Core.get_new_alerts(added_alerts, removed_alerts, ignore_readded=False)
        assert len(new_alerts) == 1

    def test_get_license_text_via_purl_uses_org_scoped_endpoint(self, core, mock_sdk):
        """Test license enrichment calls the org-scoped PURL SDK method."""
        core.sdk.purl = Mock()
        core.sdk.purl.post.return_value = [
            {
                "type": "npm",
                "name": "lodash",
                "version": "4.18.1",
                "licenseAttrib": [{"name": "MIT"}],
                "licenseDetails": [{"license": "MIT"}],
            }
        ]

        packages = {
            "npm/lodash@4.18.1": Package(
                id="pkg:npm/lodash@4.18.1",
                type="npm",
                name="lodash",
                version="4.18.1",
                score={},
                alerts=[],
                topLevelAncestors=[],
            )
        }

        result = core.get_license_text_via_purl(packages)

        core.sdk.purl.post.assert_called_once_with(
            license=True,
            components=[{"purl": "pkg:/npm/lodash@4.18.1"}],
            org_slug="test-org",
            licenseattrib=True,
            licensedetails=True,
        )
        assert result["npm/lodash@4.18.1"].licenseAttrib == [{"name": "MIT"}]
        assert result["npm/lodash@4.18.1"].licenseDetails == [{"license": "MIT"}]
