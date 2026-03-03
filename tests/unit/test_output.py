import pytest
from socketsecurity.output import OutputHandler
from socketsecurity.core.classes import Diff, Issue
import json

class TestOutputHandler:
    @pytest.fixture
    def handler(self):
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock
        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = False
        config.sarif_file = None
        config.sarif_reachable_only = False
        config.sbom_file = None
        return OutputHandler(config, Mock())

    def test_report_pass_with_blocking_issues(self, handler):
        diff = Diff()
        diff.new_alerts = [Issue(error=True)]
        assert not handler.report_pass(diff)

    def test_report_pass_with_blocking_disabled(self):
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock
        config = Mock(spec=CliConfig)
        config.disable_blocking = True
        config.strict_blocking = False
        handler = OutputHandler(config, Mock())
        diff = Diff()
        diff.new_alerts = [Issue(error=True)]
        assert handler.report_pass(diff)

    def test_json_output_format(self, handler, caplog):
        import logging
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"
        test_issue = Issue(
            title="Test",
            severity="high",
            description="Test description",
            error=True,
            key="test-key",
            type="test-type",
            pkg_type="npm",
            pkg_name="test-package",
            pkg_version="1.0.0",
            purl="pkg:npm/test-package@1.0.0"
        )
        diff.new_alerts = [test_issue]

        with caplog.at_level(logging.INFO, logger="socketcli"):
            handler.output_console_json(diff)

        output = json.loads(caplog.messages[-1])
        assert output["new_alerts"][0]["title"] == "Test"
        assert output["new_alerts"][0]["severity"] == "high"
        assert output["new_alerts"][0]["error"] is True
        assert output["new_alerts"][0]["description"] == "Test description"

    def test_sbom_file_saving(self, handler, tmp_path):
        # Test SBOM file is created correctly
        diff = Diff()
        diff.sbom = {"test": "data"}
        sbom_path = tmp_path / "test.json"
        handler.save_sbom_file(diff, str(sbom_path))
        assert sbom_path.exists()

    def test_report_pass_with_strict_blocking_new_alerts(self):
        """Test that strict-blocking fails on new blocking alerts"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        # Create config with strict_blocking
        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = True

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = [Issue(error=True, warn=False)]
        diff.unchanged_alerts = []

        assert not handler.report_pass(diff)

    def test_report_pass_with_strict_blocking_unchanged_alerts(self):
        """Test that strict-blocking fails on unchanged blocking alerts"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = True

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = []
        diff.unchanged_alerts = [Issue(error=True, warn=False)]

        assert not handler.report_pass(diff)

    def test_report_pass_with_strict_blocking_both_alerts(self):
        """Test that strict-blocking fails when both new and unchanged alerts exist"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = True

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = [Issue(error=True, warn=False)]
        diff.unchanged_alerts = [Issue(error=True, warn=False)]

        assert not handler.report_pass(diff)

    def test_report_pass_with_strict_blocking_only_warnings(self):
        """Test that strict-blocking passes when only warnings (not errors) exist"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = True

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = [Issue(error=False, warn=True)]
        diff.unchanged_alerts = [Issue(error=False, warn=True)]

        assert handler.report_pass(diff)

    def test_report_pass_strict_blocking_disabled(self):
        """Test that strict-blocking without the flag passes with unchanged alerts"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = False
        config.strict_blocking = False  # Flag not set

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = []
        diff.unchanged_alerts = [Issue(error=True, warn=False)]

        # Should pass because strict_blocking is False
        assert handler.report_pass(diff)

    def test_disable_blocking_overrides_strict_blocking(self):
        """Test that disable-blocking takes precedence over strict-blocking"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.disable_blocking = True
        config.strict_blocking = True

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.new_alerts = [Issue(error=True, warn=False)]
        diff.unchanged_alerts = [Issue(error=True, warn=False)]

        # Should pass because disable_blocking takes precedence
        assert handler.report_pass(diff)

    def test_sarif_file_output(self, tmp_path):
        """Test that --sarif-file writes SARIF report to a file"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        sarif_path = tmp_path / "report.sarif"

        config = Mock(spec=CliConfig)
        config.sarif_file = str(sarif_path)
        config.sbom_file = None

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = [Issue(
            pkg_name="test-package",
            pkg_version="1.0.0",
            severity="high",
            title="Test Vulnerability",
            description="Test description",
            type="malware",
            url="https://socket.dev/test",
            manifests="package.json",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/test-package@1.0.0",
            error=True,
        )]

        handler.output_console_sarif(diff)

        assert sarif_path.exists()
        with open(sarif_path) as f:
            sarif_data = json.load(f)
        assert sarif_data["version"] == "2.1.0"

    def test_sarif_reachable_only_filters_non_blocking(self, tmp_path):
        """Test that --sarif-reachable-only excludes non-blocking (unreachable) alerts"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        sarif_path = tmp_path / "report.sarif"

        config = Mock(spec=CliConfig)
        config.sarif_file = str(sarif_path)
        config.sarif_reachable_only = True
        config.sbom_file = None

        handler = OutputHandler(config, Mock())

        def make_issue(name, error):
            return Issue(
                pkg_name=name,
                pkg_version="1.0.0",
                severity="high",
                title=f"Vuln in {name}",
                description="test",
                type="vulnerability",
                manifests="package.json",
                pkg_type="npm",
                key=f"key-{name}",
                purl=f"pkg:npm/{name}@1.0.0",
                error=error,
            )

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = [
            make_issue("reachable-pkg", error=True),
            make_issue("unreachable-pkg", error=False),
        ]

        handler.output_console_sarif(diff)

        with open(sarif_path) as f:
            sarif_data = json.load(f)

        rule_ids = [r["ruleId"] for r in sarif_data["runs"][0]["results"]]
        assert any("reachable-pkg" in r for r in rule_ids)
        assert not any("unreachable-pkg" in r for r in rule_ids)

    def test_sarif_reachable_only_false_includes_all(self, tmp_path):
        """Test that without --sarif-reachable-only all alerts are included"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        sarif_path = tmp_path / "report.sarif"

        config = Mock(spec=CliConfig)
        config.sarif_file = str(sarif_path)
        config.sarif_reachable_only = False
        config.sbom_file = None

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = [
            Issue(pkg_name="blocking-pkg", pkg_version="1.0.0", severity="high",
                  title="Vuln", description="test", type="vulnerability",
                  manifests="package.json", pkg_type="npm", key="k1",
                  purl="pkg:npm/blocking-pkg@1.0.0", error=True),
            Issue(pkg_name="non-blocking-pkg", pkg_version="1.0.0", severity="low",
                  title="Vuln", description="test", type="vulnerability",
                  manifests="package.json", pkg_type="npm", key="k2",
                  purl="pkg:npm/non-blocking-pkg@1.0.0", error=False),
        ]

        handler.output_console_sarif(diff)

        with open(sarif_path) as f:
            sarif_data = json.load(f)

        rule_ids = [r["ruleId"] for r in sarif_data["runs"][0]["results"]]
        assert any("blocking-pkg" in r for r in rule_ids)
        assert any("non-blocking-pkg" in r for r in rule_ids)
        assert "$schema" in sarif_data
        assert len(sarif_data["runs"]) == 1

    def test_sarif_no_file_when_not_configured(self, tmp_path):
        """Test that no file is written when --sarif-file is not set"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        config = Mock(spec=CliConfig)
        config.sarif_file = None
        config.sbom_file = None

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = []

        handler.output_console_sarif(diff)

        # No files should be created in tmp_path
        assert list(tmp_path.iterdir()) == []

    def test_sarif_file_nested_directory(self, tmp_path):
        """Test that --sarif-file creates parent directories if needed"""
        from socketsecurity.config import CliConfig
        from unittest.mock import Mock

        sarif_path = tmp_path / "nested" / "dir" / "report.sarif"

        config = Mock(spec=CliConfig)
        config.sarif_file = str(sarif_path)
        config.sbom_file = None

        handler = OutputHandler(config, Mock())

        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = []

        handler.output_console_sarif(diff)

        assert sarif_path.exists()
        with open(sarif_path) as f:
            sarif_data = json.load(f)
        assert sarif_data["version"] == "2.1.0"