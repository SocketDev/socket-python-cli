from pathlib import Path
import pytest
from unittest.mock import patch
import tomllib
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

    def test_sarif_reachable_only_is_not_supported(self):
        """Legacy --sarif-reachable-only is removed; argparse should reject it."""
        with pytest.raises(SystemExit) as exc_info:
            CliConfig.from_args(self.BASE_ARGS + ["--sarif-reachable-only", "--reach"])
        assert exc_info.value.code == 2

    def test_sarif_file_implies_enable_sarif(self):
        """--sarif-file should automatically set enable_sarif=True"""
        config = CliConfig.from_args(self.BASE_ARGS + ["--sarif-file", "out.sarif"])
        assert config.enable_sarif is True
        assert config.sarif_file == "out.sarif"

    def test_sarif_scope_full_without_reach_exits(self):
        """--sarif-scope full without --reach should exit with code 1"""
        with pytest.raises(SystemExit) as exc_info:
            CliConfig.from_args(self.BASE_ARGS + ["--sarif-scope", "full"])
        assert exc_info.value.code == 1

    def test_sarif_scope_full_with_reach_succeeds(self):
        """--sarif-scope full with --reach should parse successfully"""
        config = CliConfig.from_args(self.BASE_ARGS + ["--sarif-scope", "full", "--reach"])
        assert config.sarif_scope == "full"
        assert config.reach is True

    def test_sarif_reachability_without_reach_exits(self):
        with pytest.raises(SystemExit) as exc_info:
            CliConfig.from_args(self.BASE_ARGS + ["--sarif-reachability", "reachable"])
        assert exc_info.value.code == 1

    def test_sarif_reachability_with_reach_succeeds(self):
        config = CliConfig.from_args(
            self.BASE_ARGS + ["--reach", "--sarif-scope", "full", "--sarif-reachability", "potentially"]
        )
        assert config.sarif_reachability == "potentially"
        assert config.reach is True

    def test_sarif_grouping_alert_requires_full_scope(self):
        with pytest.raises(SystemExit) as exc_info:
            CliConfig.from_args(self.BASE_ARGS + ["--reach", "--sarif-grouping", "alert"])
        assert exc_info.value.code == 1

    def test_sarif_reachability_reachable_with_reach_succeeds(self):
        config = CliConfig.from_args(self.BASE_ARGS + ["--reach", "--sarif-reachability", "reachable"])
        assert config.sarif_reachability == "reachable"

    def test_config_file_toml_sets_defaults(self, tmp_path):
        config_path = tmp_path / "socketcli.toml"
        config_path.write_text(
            "[socketcli]\n"
            "reach = true\n"
            "sarif_scope = \"full\"\n"
            "sarif_grouping = \"alert\"\n"
            "sarif_reachability = \"reachable\"\n",
            encoding="utf-8",
        )

        config = CliConfig.from_args(self.BASE_ARGS + ["--config", str(config_path)])
        assert config.reach is True
        assert config.sarif_scope == "full"
        assert config.sarif_grouping == "alert"
        assert config.sarif_reachability == "reachable"

    def test_cli_flag_overrides_config_file(self, tmp_path):
        config_path = tmp_path / "socketcli.toml"
        config_path.write_text(
            "[socketcli]\n"
            "reach = true\n"
            "sarif_scope = \"full\"\n",
            encoding="utf-8",
        )

        config = CliConfig.from_args(
            self.BASE_ARGS + ["--config", str(config_path), "--sarif-scope", "diff"]
        )
        assert config.reach is True
        assert config.sarif_scope == "diff"

    def test_config_file_json_sets_defaults(self, tmp_path):
        config_path = tmp_path / "socketcli.json"
        config_path.write_text(
            "{\"socketcli\": {\"reach\": true, \"sarif_scope\": \"full\", \"sarif_grouping\": \"alert\", \"sarif_reachability\": \"reachable\"}}",
            encoding="utf-8",
        )
        config = CliConfig.from_args(self.BASE_ARGS + ["--config", str(config_path)])
        assert config.reach is True
        assert config.sarif_scope == "full"
        assert config.sarif_grouping == "alert"
        assert config.sarif_reachability == "reachable"


def test_pyproject_requires_python_matches_tomllib_usage():
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    requires_python = pyproject["project"]["requires-python"]

    assert requires_python.startswith(">=")

    minimum_version = tuple(int(part) for part in requires_python.removeprefix(">=").split(".")[:2])
    config_module = Path("socketsecurity/config.py").read_text(encoding="utf-8")

    if "import tomllib" in config_module:
        assert minimum_version >= (3, 11)
