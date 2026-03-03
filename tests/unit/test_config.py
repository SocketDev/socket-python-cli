import pytest
from unittest.mock import patch
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.config import CliConfig

def test_config_default_values():
    """Test that config initializes with correct default values"""
    config = SocketConfig(api_key="test_key")

    assert config.api_key == "test_key"
    assert config.api_url == "https://api.socket.dev/v0"
    assert config.timeout == 1200
    assert config.allow_unverified_ssl is False
    assert config.org_id is None
    assert config.org_slug is None
    assert config.full_scan_path is None
    assert config.repository_path is None

def test_config_custom_values():
    """Test that config accepts custom values"""
    config = SocketConfig(
        api_key="test_key",
        api_url="https://custom.api.dev/v1",
        timeout=60,
        allow_unverified_ssl=True
    )

    assert config.api_key == "test_key"
    assert config.api_url == "https://custom.api.dev/v1"
    assert config.timeout == 60
    assert config.allow_unverified_ssl is True

def test_config_api_key_required():
    """Test that api_key is required"""
    with pytest.raises(ValueError):
        SocketConfig(api_key=None)

    with pytest.raises(ValueError):
        SocketConfig(api_key="")

def test_config_invalid_timeout():
    """Test that timeout must be positive"""
    with pytest.raises(ValueError):
        SocketConfig(api_key="test_key", timeout=0)

    with pytest.raises(ValueError):
        SocketConfig(api_key="test_key", timeout=-1)

def test_config_invalid_api_url():
    """Test that api_url must be valid HTTPS URL"""
    with pytest.raises(ValueError):
        SocketConfig(api_key="test_key", api_url="not_a_url")

    with pytest.raises(ValueError):
        SocketConfig(api_key="test_key", api_url="http://insecure.com")  # Must be HTTPS

def test_config_update_org_details():
    """Test updating org details"""
    config = SocketConfig(api_key="test_key")

    config.org_id = "test_org_id"
    config.org_slug = "test-org"
    config.full_scan_path = "orgs/test-org/full-scans"
    config.repository_path = "orgs/test-org/repos"

    assert config.org_id == "test_org_id"
    assert config.org_slug == "test-org"
    assert config.full_scan_path == "orgs/test-org/full-scans"
    assert config.repository_path == "orgs/test-org/repos"


class TestCliConfigValidation:
    """Tests for CliConfig argument validation"""

    BASE_ARGS = ["--api-token", "test-token", "--repo", "test-repo"]

    def test_sarif_reachable_only_without_reach_exits(self):
        """--sarif-reachable-only without --reach should exit with code 1"""
        with pytest.raises(SystemExit) as exc_info:
            CliConfig.from_args(self.BASE_ARGS + ["--sarif-reachable-only"])
        assert exc_info.value.code == 1

    def test_sarif_reachable_only_with_reach_succeeds(self):
        """--sarif-reachable-only with --reach should not raise"""
        config = CliConfig.from_args(self.BASE_ARGS + ["--sarif-reachable-only", "--reach"])
        assert config.sarif_reachable_only is True
        assert config.reach is True

    def test_sarif_file_implies_enable_sarif(self):
        """--sarif-file should automatically set enable_sarif=True"""
        config = CliConfig.from_args(self.BASE_ARGS + ["--sarif-file", "out.sarif"])
        assert config.enable_sarif is True
        assert config.sarif_file == "out.sarif"
