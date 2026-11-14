import json
import logging

import pytest
import requests

from socketsecurity.config import CliConfig, PluginConfig
from socketsecurity.core.classes import Diff
from socketsecurity.output import OutputHandler
from socketsecurity.plugins.base import REQUEST_TIMEOUT_SECONDS


@pytest.mark.parametrize("error_type", [requests.Timeout, requests.ConnectionError])
def test_jira_request_failure_preserves_scan_artifacts(tmp_path, mocker, caplog, error_type):
    config = CliConfig(api_token="test-token", repo="widgets")
    config.jira_plugin = PluginConfig(
        enabled=True,
        config={
            "url": "https://jira.example.com/private-endpoint",
            "project": "SEC",
            "email": "test@example.com",
            "api_token": "test-token",
        },
    )
    config.json_file = str(tmp_path / "report.json")
    config.summary_file = str(tmp_path / "summary.txt")
    config.report_link_file = str(tmp_path / "report-link.txt")
    config.sbom_file = str(tmp_path / "sbom.json")
    post = mocker.patch(
        "socketsecurity.plugins.jira.requests.post",
        side_effect=error_type("Request failed at https://jira.example.com/private-endpoint?token=secret"),
    )
    diff = Diff(id="scan", diff_url="https://socket.dev/report", sbom={"packages": []})
    handler = OutputHandler(config, sdk=mocker.Mock())

    with caplog.at_level(logging.ERROR, logger="socketcli"):
        handler.handle_output(diff)

    assert json.loads((tmp_path / "report.json").read_text())["full_scan_id"] == "scan"
    assert (tmp_path / "summary.txt").read_text().strip() == "No issues found"
    assert (tmp_path / "report-link.txt").read_text().strip() == diff.diff_url
    assert json.loads((tmp_path / "sbom.json").read_text()) == diff.sbom
    assert handler.return_exit_code(diff) == 0
    assert post.call_args.kwargs["timeout"] == REQUEST_TIMEOUT_SECONDS
    assert f"Jira request failed ({error_type.__name__})" in caplog.text
    assert "https://jira.example.com/***redacted***" in caplog.text
    assert "private-endpoint" not in caplog.text
    assert "token=secret" not in caplog.text
