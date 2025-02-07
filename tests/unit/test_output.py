import pytest
from socketsecurity.output import OutputHandler
from socketsecurity.core.classes import Diff, Issue
import json

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