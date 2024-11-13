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
        diff.issues = [Issue(blocking=True)]
        assert not handler.report_pass(diff)

    def test_report_pass_with_blocking_disabled(self):
        handler = OutputHandler(blocking_disabled=True)
        diff = Diff()
        diff.issues = [Issue(blocking=True)]
        assert handler.report_pass(diff)

    def test_json_output_format(self, handler, capsys):
        diff = Diff()
        test_issue = Issue(
            title="Test",
            severity="high",
            blocking=True,
            description="Test description",
            recommendation=None
        )
        diff.issues = [test_issue]

        handler.output_console_json(diff)
        captured = capsys.readouterr()

        # Parse the JSON output and verify structure
        output = json.loads(captured.out)
        assert output["issues"][0]["title"] == "Test"
        assert output["issues"][0]["severity"] == "high"
        assert output["issues"][0]["blocking"] is True
        assert output["issues"][0]["description"] == "Test description"
        assert output["issues"][0]["recommendation"] is None

    def test_sbom_file_saving(self, handler, tmp_path):
        # Test SBOM file is created correctly
        diff = Diff()
        diff.sbom = {"test": "data"}
        sbom_path = tmp_path / "test.json"
        handler.save_sbom_file(diff, str(sbom_path))
        assert sbom_path.exists()