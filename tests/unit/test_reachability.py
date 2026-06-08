"""Tests for the reachability coana-CLI command/env construction (Node alignment).

These cover the arg-builder and environment wiring in
``socketsecurity.core.tools.reachability.ReachabilityAnalyzer`` without actually
invoking npx/coana: ``_resolve_coana_package_spec`` and ``subprocess.run`` are mocked.
"""
from unittest.mock import MagicMock

import pytest

from socketsecurity import __version__
from socketsecurity.core.tools import reachability
from socketsecurity.core.tools.reachability import (
    DEFAULT_COANA_CLI_VERSION,
    ReachabilityAnalyzer,
    _build_caller_user_agent,
)


@pytest.fixture
def analyzer():
    return ReachabilityAnalyzer(MagicMock(), "test-api-token")


def _run(analyzer, mocker, **kwargs):
    """Invoke run_reachability_analysis with the spec resolver/coana mocked; return (cmd, env)."""
    mocker.patch.object(
        analyzer,
        "_resolve_coana_package_spec",
        return_value=f"@coana-tech/cli@{DEFAULT_COANA_CLI_VERSION}",
    )
    mocker.patch.object(analyzer, "_extract_scan_id", return_value="scan-123")
    completed = MagicMock()
    completed.returncode = 0
    run_mock = mocker.patch.object(reachability.subprocess, "run", return_value=completed)

    analyzer.run_reachability_analysis(org_slug="my-org", target_directory=".", **kwargs)

    cmd = run_mock.call_args.args[0]
    env = run_mock.call_args.kwargs["env"]
    return cmd, env


def test_build_caller_user_agent_shape():
    ua = _build_caller_user_agent()
    parts = ua.split(" ")
    assert parts[0] == f"socket/{__version__}"
    assert parts[1].startswith("python/")
    assert "/" in parts[2]  # platform/arch


def test_reach_debug_appends_debug_long_flag(analyzer, mocker):
    """G9: --reach-debug -> coana --debug; does not emit the global -d."""
    cmd, _ = _run(analyzer, mocker, reach_debug=True)
    assert "--debug" in cmd
    assert "-d" not in cmd


def test_enable_debug_still_emits_short_d(analyzer, mocker):
    """G9: existing global --enable-debug -> -d behavior is unchanged."""
    cmd, _ = _run(analyzer, mocker, enable_debug=True)
    assert "-d" in cmd
    assert "--debug" not in cmd


def test_disable_external_tool_checks(analyzer, mocker):
    """G1: --reach-disable-external-tool-checks -> coana --disable-external-tool-checks."""
    cmd, _ = _run(analyzer, mocker, disable_external_tool_checks=True)
    assert "--disable-external-tool-checks" in cmd

    cmd2, _ = _run(analyzer, mocker)
    assert "--disable-external-tool-checks" not in cmd2


def test_concurrency_and_memory_args(analyzer, mocker):
    """G7: explicit concurrency/memory propagate as coana args."""
    cmd, _ = _run(analyzer, mocker, concurrency=1, memory_limit=8192)
    assert "--concurrency" in cmd and cmd[cmd.index("--concurrency") + 1] == "1"
    assert "--memory-limit" in cmd and cmd[cmd.index("--memory-limit") + 1] == "8192"


def test_env_identifies_python_cli(analyzer, mocker):
    """G5: SOCKET_CLI_VERSION + SOCKET_CALLER_USER_AGENT forwarded to coana."""
    _, env = _run(analyzer, mocker)
    assert env["SOCKET_CLI_VERSION"] == __version__
    assert env["SOCKET_CALLER_USER_AGENT"].startswith("socket/")
    assert env["SOCKET_ORG_SLUG"] == "my-org"
    assert env["SOCKET_CLI_API_TOKEN"] == "test-api-token"


def test_no_proxy_env_set_by_default(analyzer, mocker, monkeypatch):
    """coana inherits HTTPS_PROXY/HTTP_PROXY from the passed env; we don't set
    SOCKET_CLI_API_PROXY ourselves (that's reserved for a future explicit --proxy flag)."""
    monkeypatch.delenv("SOCKET_CLI_API_PROXY", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://envproxy:3128")
    _, env = _run(analyzer, mocker)
    # Even with HTTPS_PROXY set, we don't copy it into SOCKET_CLI_API_PROXY (coana reads it itself).
    assert "SOCKET_CLI_API_PROXY" not in env


def test_repo_branch_env_present_when_supplied(analyzer, mocker):
    _, env = _run(analyzer, mocker, repo_name="acme/widget", branch_name="main")
    assert env["SOCKET_REPO_NAME"] == "acme/widget"
    assert env["SOCKET_BRANCH_NAME"] == "main"


def test_repo_branch_env_absent_when_none(analyzer, mocker):
    """G6: caller passes None for default sentinels -> env keys omitted (cache hygiene)."""
    _, env = _run(analyzer, mocker, repo_name=None, branch_name=None)
    assert "SOCKET_REPO_NAME" not in env
    assert "SOCKET_BRANCH_NAME" not in env


# --- Coana package-spec resolution (pinned by default, latest is opt-in) ---


def test_resolve_spec_defaults_to_pinned_version(analyzer):
    """No --reach-version -> pinned DEFAULT_COANA_CLI_VERSION (no auto-update)."""
    assert (
        analyzer._resolve_coana_package_spec(None)
        == f"@coana-tech/cli@{DEFAULT_COANA_CLI_VERSION}"
    )


def test_resolve_spec_pins_explicit_version(analyzer):
    assert analyzer._resolve_coana_package_spec("1.2.3") == "@coana-tech/cli@1.2.3"


def test_resolve_spec_latest_opt_in(analyzer):
    """'latest' opts into the newest published version."""
    assert analyzer._resolve_coana_package_spec("latest") == "@coana-tech/cli@latest"


def test_resolve_spec_is_always_versioned(analyzer):
    """Never the bare '@coana-tech/cli' (which would let npx pick a stray global version)."""
    for version in (None, "latest", "1.2.3", " 1.2.3 "):
        assert analyzer._resolve_coana_package_spec(version).startswith("@coana-tech/cli@")


def _run_with_real_resolver(analyzer, mocker, **kwargs):
    """Like _run but exercises the real _resolve_coana_package_spec; returns the run mock."""
    mocker.patch.object(analyzer, "_extract_scan_id", return_value="scan-123")
    completed = MagicMock()
    completed.returncode = 0
    run_mock = mocker.patch.object(reachability.subprocess, "run", return_value=completed)
    analyzer.run_reachability_analysis(org_slug="my-org", target_directory=".", **kwargs)
    return run_mock


def test_npx_runs_pinned_version_by_default(analyzer, mocker):
    run_mock = _run_with_real_resolver(analyzer, mocker)
    cmd = run_mock.call_args.args[0]
    assert cmd[0] == "npx"
    assert cmd[1] == f"@coana-tech/cli@{DEFAULT_COANA_CLI_VERSION}"


def test_npx_runs_explicit_version(analyzer, mocker):
    run_mock = _run_with_real_resolver(analyzer, mocker, version="9.9.9")
    assert run_mock.call_args.args[0][1] == "@coana-tech/cli@9.9.9"


def test_npx_runs_latest_when_opted_in(analyzer, mocker):
    run_mock = _run_with_real_resolver(analyzer, mocker, version="latest")
    assert run_mock.call_args.args[0][1] == "@coana-tech/cli@latest"


def test_never_runs_npm_install(analyzer, mocker):
    """Core guarantee: we never `npm install -g` (no auto-update / global mutation)."""
    run_mock = _run_with_real_resolver(analyzer, mocker)
    for call in run_mock.call_args_list:
        argv = call.args[0]
        assert argv[:2] != ["npm", "install"]
