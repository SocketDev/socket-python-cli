import pytest
from socketsecurity.config import CliConfig

class TestCliConfig:
    def test_api_token_from_env(self, monkeypatch):
        monkeypatch.setenv("SOCKET_SECURITY_API_KEY", "test-token")
        config = CliConfig.from_args([])  # Empty args list
        assert config.api_token == "test-token"

    def test_required_args(self):
        """Test that api token is required if not in environment"""
        with pytest.raises(ValueError, match="API token is required"):
            config = CliConfig.from_args([])
            if not config.api_token:
                raise ValueError("API token is required")

    def test_default_values(self):
        # Test that default values are set correctly
        config = CliConfig.from_args(["--api-token", "test"])
        assert config.branch == ""
        assert config.target_path == "./"
        assert config.files == "[]"

    @pytest.mark.parametrize("flag,attr", [
        ("--enable-debug", "enable_debug"),
        ("--disable-blocking", "disable_blocking"),
        ("--allow-unverified", "allow_unverified"),
        ("--enable-diff", "enable_diff")
    ])
    def test_boolean_flags(self, flag, attr):
        config = CliConfig.from_args(["--api-token", "test", flag])
        assert getattr(config, attr) is True

    def test_enable_diff_default_false(self):
        """Test that enable_diff defaults to False"""
        config = CliConfig.from_args(["--api-token", "test"])
        assert config.enable_diff is False

    def test_enable_diff_with_integration_api(self):
        """Test that enable_diff can be used with integration api"""
        config = CliConfig.from_args(["--api-token", "test", "--integration", "api", "--enable-diff"])
        assert config.enable_diff is True
        assert config.integration_type == "api"