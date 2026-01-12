import pytest
from socketsecurity.output import OutputHandler
from socketsecurity.core.classes import Diff, Issue
from socketsecurity.config import CliConfig
import json
from unittest.mock import Mock
from pathlib import Path

class TestOutputHandler:
    @pytest.fixture
    def handler(self):
        return OutputHandler(blocking_disabled=False)

    def test_report_pass_with_blocking_issues(self, handler):
        diff = Diff()
        diff.new_alerts = [Issue(error=True)]
        assert not handler.report_pass(diff)

    def test_report_pass_with_blocking_disabled(self):
        handler = OutputHandler(blocking_disabled=True)
        diff = Diff()
        diff.new_alerts = [Issue(error=True)]
        assert handler.report_pass(diff)

    def test_json_output_format(self, handler, capsys):
        diff = Diff()
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

        handler.output_console_json(diff)
        captured = capsys.readouterr()

        # Parse the JSON output and verify structure
        output = json.loads(captured.out)
        assert output["issues"][0]["title"] == "Test"
        assert output["issues"][0]["severity"] == "high"
        assert output["issues"][0]["blocking"] is True
        assert output["issues"][0]["description"] == "Test description"

    def test_sbom_file_saving(self, handler, tmp_path):
        # Test SBOM file is created correctly
        diff = Diff()
        diff.sbom = {"test": "data"}
        sbom_path = tmp_path / "test.json"
        handler.save_sbom_file(diff, str(sbom_path))
        assert sbom_path.exists()

    def test_gitlab_security_output_enabled(self, tmp_path):
        """Test GitLab security report is generated when flag enabled"""
        config = CliConfig(
            api_token="test",
            repo="test/repo",
            enable_gitlab_security=True,
            gitlab_security_file=str(tmp_path / "test-report.json")
        )

        mock_sdk = Mock()
        handler = OutputHandler(config=config, sdk=mock_sdk)

        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"
        test_issue = Issue(
            pkg_name="test-pkg",
            pkg_version="1.0.0",
            severity="high",
            title="Test",
            type="malware",
            manifests="package.json",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/test-pkg@1.0.0"
        )
        diff.new_alerts = [test_issue]

        handler.handle_output(diff)

        # Verify file was created
        report_path = tmp_path / "test-report.json"
        assert report_path.exists()

        # Verify content structure
        with open(report_path) as f:
            report = json.load(f)

        assert report["scan"]["type"] == "dependency_scanning"
        assert len(report["vulnerabilities"]) == 1
        assert report["vulnerabilities"][0]["name"] == "Test"
        assert report["vulnerabilities"][0]["severity"] == "High"

    def test_multiple_formats_simultaneously(self, tmp_path, capsys):
        """Test multiple output formats can be enabled together"""
        config = CliConfig(
            api_token="test",
            repo="test/repo",
            enable_json=True,
            enable_gitlab_security=True,
            gitlab_security_file=str(tmp_path / "gitlab.json")
        )

        mock_sdk = Mock()
        handler = OutputHandler(config=config, sdk=mock_sdk)

        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"
        diff.sbom = {"test": "sbom"}
        test_issue = Issue(
            pkg_name="test-pkg",
            pkg_version="1.0.0",
            severity="high",
            title="Test Issue",
            type="malware",
            pkg_type="npm",
            key="test-key",
            purl="pkg:npm/test-pkg@1.0.0"
        )
        diff.new_alerts = [test_issue]

        handler.handle_output(diff)

        # JSON should be output to console (captured)
        captured = capsys.readouterr()
        assert len(captured.out) > 0

        # GitLab file should exist
        gitlab_path = tmp_path / "gitlab.json"
        assert gitlab_path.exists()

        # Verify GitLab content
        with open(gitlab_path) as f:
            gitlab_report = json.load(f)
        assert gitlab_report["scan"]["type"] == "dependency_scanning"

    def test_gitlab_security_file_default_path(self, tmp_path, monkeypatch):
        """Test GitLab security report uses default filename"""
        # Change to tmp directory for this test
        monkeypatch.chdir(tmp_path)

        config = CliConfig(
            api_token="test",
            repo="test/repo",
            enable_gitlab_security=True
        )

        mock_sdk = Mock()
        handler = OutputHandler(config=config, sdk=mock_sdk)

        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"
        diff.new_alerts = []

        handler.handle_output(diff)

        # Should create file with default name
        default_path = tmp_path / "gl-dependency-scanning-report.json"
        assert default_path.exists()

    def test_gitlab_output_skipped_when_no_diff(self):
        """Test GitLab output is skipped when NO_DIFF_RAN"""
        config = CliConfig(
            api_token="test",
            repo="test/repo",
            enable_gitlab_security=True,
            gitlab_security_file="test-report.json"
        )

        mock_sdk = Mock()
        handler = OutputHandler(config=config, sdk=mock_sdk)

        diff = Diff()
        diff.id = "NO_DIFF_RAN"
        diff.new_alerts = []

        handler.handle_output(diff)

        # File should not be created
        assert not Path("test-report.json").exists()

    def test_gitlab_security_creates_parent_directories(self, tmp_path):
        """Test GitLab security file creation creates parent directories"""
        config = CliConfig(
            api_token="test",
            repo="test/repo",
            enable_gitlab_security=True,
            gitlab_security_file=str(tmp_path / "reports" / "security" / "gitlab.json")
        )

        mock_sdk = Mock()
        handler = OutputHandler(config=config, sdk=mock_sdk)

        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"
        diff.new_alerts = []

        handler.handle_output(diff)

        # Verify parent directories were created
        report_path = tmp_path / "reports" / "security" / "gitlab.json"
        assert report_path.exists()
        assert report_path.parent.exists()