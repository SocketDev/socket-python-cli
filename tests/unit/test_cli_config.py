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

    def test_strict_blocking_flag(self):
        """Test that --strict-blocking flag is parsed correctly"""
        config = CliConfig.from_args(["--api-token", "test", "--strict-blocking"])
        assert config.strict_blocking is True

    def test_strict_blocking_default_false(self):
        """Test that strict_blocking defaults to False"""
        config = CliConfig.from_args(["--api-token", "test"])
        assert config.strict_blocking is False

    def test_strict_blocking_with_disable_blocking(self):
        """Test that both flags can be set (disable-blocking should win)"""
        config = CliConfig.from_args([
            "--api-token", "test",
            "--strict-blocking",
            "--disable-blocking"
        ])
        assert config.strict_blocking is True
        assert config.disable_blocking is True

    def test_workspace_flag(self):
        """Test that --workspace is parsed and stored correctly."""
        config = CliConfig.from_args(["--api-token", "test", "--workspace", "grofers"])
        assert config.workspace == "grofers"

    def test_workspace_default_is_none(self):
        """Test that workspace defaults to None when not supplied."""
        config = CliConfig.from_args(["--api-token", "test"])
        assert config.workspace is None

    def test_workspace_is_independent_of_workspace_name(self):
        """--workspace and --workspace-name are distinct flags with distinct purposes."""
        config = CliConfig.from_args([
            "--api-token", "test",
            "--workspace", "grofers",
            "--sub-path", ".",
            "--workspace-name", "monorepo-suffix",
        ])
        assert config.workspace == "grofers"
        assert config.workspace_name == "monorepo-suffix"