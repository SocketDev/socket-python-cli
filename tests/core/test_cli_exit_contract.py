"""Exercise the public exit contract through argument parsing and the CLI flow."""

import json
import os
import signal
import subprocess
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from socketsecurity import socketcli
from socketsecurity.config import CliConfig, create_argument_parser, parse_files
from socketsecurity.core import Core
from socketsecurity.core.classes import Diff, Issue, Package
from socketsecurity.exit_codes import InfrastructureError

POLICIES = [
    pytest.param([], 3, id="default"),
    pytest.param(["--exit-code-on-api-error", "100"], 100, id="remap"),
    pytest.param(["--exit-code-on-api-error", "0"], 0, id="remap-zero"),
    pytest.param(["--disable-blocking"], 0, id="nonblocking"),
    pytest.param(["--disable-blocking", "--exit-code-on-api-error", "100"], 0, id="both"),
]
TOKEN_VARS = (
    "SOCKET_SECURITY_API_KEY", "SOCKET_SECURITY_API_TOKEN", "SOCKET_API_KEY", "SOCKET_API_TOKEN",
    "GH_API_TOKEN", "GITLAB_TOKEN",
)


@pytest.fixture
def cli_runtime(monkeypatch):
    for name in TOKEN_VARS:
        monkeypatch.delenv(name, raising=False)
    sdk = MagicMock()
    sdk.org.get.return_value = {"organizations": {"org-id": {"slug": "acme", "plan": "enterprise"}}}
    monkeypatch.setattr(socketcli, "build_socket_sdk", Mock(return_value=sdk))
    monkeypatch.setattr(socketcli, "CliClient", Mock())
    monkeypatch.setattr(socketcli, "StreamingLogs", lambda **kwargs: nullcontext(Mock()))
    monkeypatch.setattr(socketcli, "apply_git_context", lambda config: (False, None))
    monkeypatch.setattr(Core, "has_manifest_files", Mock(return_value=True))
    monkeypatch.setattr(Core, "find_files", Mock(return_value=[]))
    diff = Diff(id="scan")
    scan = Mock(return_value=diff)
    monkeypatch.setattr(Core, "create_new_diff", scan)
    monkeypatch.setattr(socketcli.OutputHandler, "handle_output", Mock())
    monkeypatch.setattr(socketcli.shutil, "which", lambda dep: f"/bin/{dep}")

    def run(flags=(), *, token=True):
        argv = ["socketcli", "--enable-diff", "--repo", "repo", "--branch", "feature"]
        if token:
            argv += ["--api-token", "test"]
        monkeypatch.setattr(sys, "argv", [*argv, *flags])
        with pytest.raises(SystemExit) as result:
            socketcli.cli()
        return result.value.code

    return SimpleNamespace(sdk=sdk, scan=scan, diff=diff, run=run)


@pytest.mark.parametrize("policy, infrastructure_code", POLICIES)
@pytest.mark.parametrize("stage", [
    "socket-token", "github-token", "gitlab-token", "reach-dependency", "reach-plan", "reach-org",
])
def test_setup_failures_follow_exit_policy(cli_runtime, monkeypatch, policy, infrastructure_code, stage):
    flags = list(policy)
    if stage.endswith("-token") and stage != "socket-token":
        flags += ["--scm", stage.removesuffix("-token")]
    elif stage.startswith("reach-"):
        flags += ["--reach"]
        if stage == "reach-dependency":
            monkeypatch.setattr(socketcli.shutil, "which", lambda dep: None)
        elif stage == "reach-plan":
            cli_runtime.sdk.org.get.return_value["organizations"]["org-id"]["plan"] = "free"
        elif stage == "reach-org":
            cli_runtime.sdk.org.get.return_value = {"organizations": {}}

    assert cli_runtime.run(flags, token=stage != "socket-token") == infrastructure_code
    cli_runtime.scan.assert_not_called()


@pytest.mark.parametrize("policy, infrastructure_code", POLICIES)
@pytest.mark.parametrize("outcome, expected", [
    ("clean", 0), ("warning", 0), ("new-blocker", 1), ("existing-blocker", 0),
    ("strict-existing-blocker", 1), ("infrastructure", 3), ("interrupt", 130),
])
def test_scan_outcomes_follow_exit_policy(cli_runtime, policy, infrastructure_code, outcome, expected):
    flags = list(policy)
    if outcome in ("new-blocker", "warning"):
        cli_runtime.diff.new_alerts = [Issue(error=outcome == "new-blocker", warn=outcome == "warning")]
    elif outcome.endswith("existing-blocker"):
        cli_runtime.diff.unchanged_alerts = [Issue(error=True)]
        if outcome.startswith("strict-"):
            flags.append("--strict-blocking")
    elif outcome == "infrastructure":
        cli_runtime.scan.side_effect = RuntimeError("unexpected scan failure")
        expected = infrastructure_code
    elif outcome == "interrupt":
        cli_runtime.scan.side_effect = KeyboardInterrupt()
    if "--disable-blocking" in policy:
        expected = 0

    assert cli_runtime.run(flags) == expected
    cli_runtime.scan.assert_called_once()


@pytest.mark.parametrize("policy, infrastructure_code", POLICIES)
@pytest.mark.parametrize("flags", [
    ["--files", "not-json"], ["--files", "null"], ["--files", "{}"],
    ["--files", "[1]"], ["--timeout", "0"], ["--timeout", "-1"],
])
def test_usage_errors_fail_before_setup(cli_runtime, policy, infrastructure_code, flags):
    # Missing credentials must not hide invalid input, even in nonblocking mode.
    assert cli_runtime.run([*policy, *flags], token=False) == 2
    socketcli.build_socket_sdk.assert_not_called()


@pytest.mark.parametrize("setting", [
    {"strict_blocking": "false"}, {"timeout": 0}, {"timeout": 1.5},
    {"sarif_scope": "invalid"}, {"target_path": 123}, {"socketcli": []},
])
def test_invalid_config_file_is_a_usage_error(tmp_path, setting):
    path = tmp_path / "socketcli.json"
    path.write_text(json.dumps(setting))
    with pytest.raises(SystemExit) as result:
        CliConfig.from_args(["--config", str(path), "--disable-blocking"])
    assert result.value.code == 2


def test_config_cannot_enable_nonblocking_mode_with_a_string(tmp_path):
    path = tmp_path / "socketcli.json"
    path.write_text(json.dumps({"disable_blocking": "false"}))

    with pytest.raises(SystemExit) as result:
        CliConfig.from_args(["--config", str(path)])

    assert result.value.code == 2


def test_cli_overrides_invalid_config_defaults_before_validation(tmp_path):
    path = tmp_path / "socketcli.json"
    path.write_text(json.dumps({"strict_blocking": "false", "timeout": 0, "sarif_scope": "invalid"}))

    config = CliConfig.from_args([
        "--config", str(path), "--strict-blocking", "--timeout", "30", "--sarif-scope", "diff",
    ])

    assert config.strict_blocking is True
    assert config.timeout == 30
    assert config.sarif_scope == "diff"


@pytest.mark.parametrize("config_kind", ["directory", "invalid-utf8"])
def test_unreadable_config_is_a_usage_error(tmp_path, config_kind):
    path = tmp_path / "socketcli.json"
    if config_kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"\xff")

    with pytest.raises(SystemExit) as result:
        CliConfig.from_args(["--config", str(path), "--disable-blocking"])

    assert result.value.code == 2


@pytest.mark.parametrize("files", [
    '["package.json"]', "['package.json']", "'[\"package.json\"]'", ["package.json"],
])
def test_supported_file_list_formats_are_preserved(files):
    assert parse_files(files) == ["package.json"]


def test_help_describes_the_current_exit_contract():
    help_text = " ".join(create_argument_parser().format_help().split())

    assert "warnings alone exit 0" in help_text
    assert "Invalid flags or configuration still exit 2" in help_text
    assert "Ctrl+C (130) are unaffected" in help_text
    assert "5 for warnings" not in help_text


@pytest.mark.parametrize("policy, infrastructure_code", POLICIES)
def test_exit_policy_survives_config_file_removal(
    cli_runtime, tmp_path, policy, infrastructure_code
):
    path = tmp_path / "socketcli.json"
    path.write_text("{}")

    def fail_after_config_cleanup(*args, **kwargs):
        path.unlink()
        raise InfrastructureError("scan comparison failed")

    cli_runtime.scan.side_effect = fail_after_config_cleanup

    assert cli_runtime.run([*policy, "--config", str(path)]) == infrastructure_code


@pytest.mark.parametrize("policy, infrastructure_code", POLICIES)
def test_temporary_findings_override_does_not_change_error_policy(
    cli_runtime, monkeypatch, policy, infrastructure_code
):
    def fail_after_findings_override(handler, diff):
        handler.config.disable_blocking = True
        raise InfrastructureError("commit status failed")

    monkeypatch.setattr(socketcli.OutputHandler, "handle_output", fail_after_findings_override)

    assert cli_runtime.run(policy) == infrastructure_code


@pytest.mark.parametrize("policy, infrastructure_code", POLICIES)
def test_missing_existing_alert_data_reaches_cli_exit_policy(cli_runtime, policy, infrastructure_code):
    package = Package(id="pkg", type="npm", name="pkg", version="1", score={}, alerts=[])
    cli_runtime.sdk.fullscans.stream.return_value = SimpleNamespace(success=True, artifacts={})
    # Run the real hydration step from the scan boundary without making any network request.
    def compare(*args, **kwargs):
        core = Core.__new__(Core)
        core.sdk = cli_runtime.sdk
        core.config = SimpleNamespace(org_slug="acme")
        core.add_existing_alerts_from_full_scan({package.id: package}, "new")

    cli_runtime.scan.side_effect = compare

    assert cli_runtime.run([*policy, "--strict-blocking"]) == infrastructure_code


@pytest.mark.parametrize("policy, infrastructure_code", POLICIES)
def test_real_sigint_uses_documented_exit_status(policy, infrastructure_code):
    script = """
import time
from socketsecurity import socketcli
def wait_for_interrupt(config=None):
    print("READY", flush=True)
    time.sleep(30)
socketcli.main_code = wait_for_interrupt
socketcli.cli()
"""
    env = {key: value for key, value in os.environ.items() if key not in TOKEN_VARS}
    with subprocess.Popen(
        [sys.executable, "-c", script, "--api-token", "test", *policy],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
    ) as process:
        try:
            assert process.stdout.readline().strip() == "READY"
            process.send_signal(signal.SIGINT)
            _, stderr = process.communicate(timeout=10)
            assert process.returncode == (0 if "--disable-blocking" in policy else 130), stderr
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()


@pytest.mark.parametrize("output_flag", [[], ["--enable-json"], ["--enable-sarif"], ["--enable-gitlab-security"]])
@pytest.mark.parametrize("strict", [False, True])
def test_branch_full_scan_does_not_gate_on_findings(cli_runtime, monkeypatch, output_flag, strict):
    monkeypatch.setenv("GH_API_TOKEN", "test")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/repo")
    monkeypatch.setenv("BUILDKITE", "false")
    monkeypatch.delenv("PR_NUMBER", raising=False)
    full_scan = Mock(return_value=Diff(id="full", new_alerts=[Issue(error=True)]))
    monkeypatch.setattr(Core, "create_full_scan_with_report_url", full_scan)
    flags = ["--scm", "github", "--pr-number", "0", *output_flag]
    if strict:
        flags.append("--strict-blocking")

    assert cli_runtime.run(flags) == 0
    full_scan.assert_called_once()
    cli_runtime.scan.assert_not_called()


@pytest.mark.parametrize("scm, event, action", [
    ("github", "pull_request", "closed"), ("github", "unsupported", ""),
    ("github", "pull_request_target", "opened"), ("gitlab", "unsupported", ""),
])
def test_scm_event_filters_skip_without_scanning(cli_runtime, monkeypatch, caplog, scm, event, action):
    monkeypatch.setenv("GH_API_TOKEN", "test")
    monkeypatch.setenv("GITLAB_TOKEN", "test")
    monkeypatch.setenv("GITHUB_EVENT_NAME", event)
    monkeypatch.setenv("EVENT_ACTION", action)
    monkeypatch.setenv("CI_PIPELINE_SOURCE", event)

    with caplog.at_level("INFO", logger="socketdev"):
        assert cli_runtime.run(["--scm", scm]) == 0
    cli_runtime.scan.assert_not_called()
    assert any(
        record.levelname == "WARNING" and "No scan ran" in record.getMessage()
        for record in caplog.records
    )
