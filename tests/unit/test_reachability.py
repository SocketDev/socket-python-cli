"""Tests for the reachability coana-CLI command/env construction (Node alignment).

These cover the arg-builder, the npx launcher (caching disabled via --yes --force), the
npm-install + node fallback, and the environment wiring in
``socketsecurity.core.tools.reachability.ReachabilityAnalyzer`` without actually invoking
npx/npm/node/coana: ``subprocess.run`` (and, for the fallback, ``tempfile.mkdtemp`` /
``_resolve_coana_bin``) are mocked.
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


def _spawn_mock(analyzer, mocker, returncode=0, **kwargs):
    """Run run_reachability_analysis with subprocess.run mocked to a fixed exit code.

    Uses the real resolver / _spawn_coana; returns the run mock for inspection.
    """
    mocker.patch.object(analyzer, "_extract_scan_id", return_value="scan-123")
    completed = MagicMock()
    completed.returncode = returncode
    run_mock = mocker.patch.object(reachability.subprocess, "run", return_value=completed)

    analyzer.run_reachability_analysis(org_slug="my-org", target_directory=".", **kwargs)
    return run_mock


def _run(analyzer, mocker, **kwargs):
    """Invoke run_reachability_analysis on the happy npx path; return (npx argv, env)."""
    run_mock = _spawn_mock(analyzer, mocker, **kwargs)
    return run_mock.call_args.args[0], run_mock.call_args.kwargs["env"]


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


def _spec_in(cmd):
    """The @coana-tech/cli@<version> spec from an npx argv (it follows the npx flags)."""
    return next(a for a in cmd if a.startswith("@coana-tech/cli@"))


def test_npx_disables_cache_with_yes_and_force(analyzer, mocker):
    """npx caching is disabled via --yes --force (parity with the Node CLI dlx path)."""
    cmd, _ = _run(analyzer, mocker)
    assert cmd[0] == "npx"
    assert "--yes" in cmd
    assert "--force" in cmd


def test_npx_runs_pinned_version_by_default(analyzer, mocker):
    cmd, _ = _run(analyzer, mocker)
    assert _spec_in(cmd) == f"@coana-tech/cli@{DEFAULT_COANA_CLI_VERSION}"


def test_npx_runs_explicit_version(analyzer, mocker):
    cmd, _ = _run(analyzer, mocker, version="9.9.9")
    assert _spec_in(cmd) == "@coana-tech/cli@9.9.9"


def test_npx_runs_latest_when_opted_in(analyzer, mocker):
    cmd, _ = _run(analyzer, mocker, version="latest")
    assert _spec_in(cmd) == "@coana-tech/cli@latest"


def test_default_path_never_runs_npm_install(analyzer, mocker):
    """On the happy path we use npx only — no `npm install` (no global mutation)."""
    run_mock = _spawn_mock(analyzer, mocker)
    for call in run_mock.call_args_list:
        assert call.args[0][:2] != ["npm", "install"]


def test_env_strips_npm_package_vars(analyzer, mocker, monkeypatch):
    """npm_package_* dropped (E2BIG guard); npm_config_* kept. Parity with the Node CLI."""
    monkeypatch.setenv("npm_package_dependencies_foo", "1.0.0")
    monkeypatch.setenv("npm_config_registry", "https://example.test")
    _, env = _run(analyzer, mocker)
    assert "npm_package_dependencies_foo" not in env
    assert env.get("npm_config_registry") == "https://example.test"


# --- npm-install + node fallback (when the npx launcher fails before coana starts) ---


def test_launcher_failure_heuristic():
    f = ReachabilityAnalyzer._npx_launcher_failed_before_coana
    # Signal kills / >=128 -> launcher failure -> retry.
    assert f(-9) is True
    assert f(137) is True
    assert f(249) is True
    # Small positive exit codes are ambiguous (coana's own codes) -> do NOT retry.
    assert f(1) is False
    assert f(2) is False
    assert f(127) is False


def _capture_spawns(analyzer, mocker, npx_behavior, **kwargs):
    """Drive run_reachability_analysis capturing each spawned argv.

    ``npx_behavior`` is applied when argv[0] == 'npx': an int return code, or a
    callable raising (e.g. FileNotFoundError). npm/node spawns always succeed.
    """
    mocker.patch.object(analyzer, "_extract_scan_id", return_value="scan-123")
    mocker.patch.object(reachability.tempfile, "mkdtemp", return_value="/tmp/socket-coana-x")
    mocker.patch.object(
        analyzer,
        "_resolve_coana_bin",
        return_value="/tmp/socket-coana-x/node_modules/@coana-tech/cli/coana.js",
    )
    calls = []

    def fake_run(argv, **_kw):
        calls.append(argv)
        if argv[0] == "npx" and callable(npx_behavior):
            npx_behavior()
        m = MagicMock()
        m.returncode = npx_behavior if (argv[0] == "npx" and isinstance(npx_behavior, int)) else 0
        return m

    mocker.patch.object(reachability.subprocess, "run", side_effect=fake_run)
    analyzer.run_reachability_analysis(org_slug="my-org", target_directory=".", **kwargs)
    return calls


def test_falls_back_to_npm_install_when_npx_launcher_fails(analyzer, mocker):
    """npx exits >=128 (launcher died) -> npm install + node run coana directly."""
    calls = _capture_spawns(analyzer, mocker, npx_behavior=137)
    assert calls[0][0] == "npx"
    assert calls[1][:2] == ["npm", "install"]
    assert f"@coana-tech/cli@{DEFAULT_COANA_CLI_VERSION}" in calls[1]
    assert calls[2][0] == "node"
    assert calls[2][1] == "/tmp/socket-coana-x/node_modules/@coana-tech/cli/coana.js"
    assert calls[2][2:4] == ["run", "."]


def test_falls_back_when_npx_missing(analyzer, mocker):
    """npx not on PATH (FileNotFoundError) -> npm install + node fallback."""
    def raise_enoent():
        raise FileNotFoundError("npx")

    calls = _capture_spawns(analyzer, mocker, npx_behavior=raise_enoent)
    assert calls[0][0] == "npx"
    assert calls[1][:2] == ["npm", "install"]
    assert calls[2][0] == "node"


def test_no_fallback_on_ambiguous_exit_code(analyzer, mocker):
    """A small positive npx exit (coana's own failure) does NOT trigger the npm fallback."""
    mocker.patch.object(analyzer, "_extract_scan_id", return_value=None)
    calls = []

    def fake_run(argv, **_kw):
        calls.append(argv)
        m = MagicMock()
        m.returncode = 1
        return m

    mocker.patch.object(reachability.subprocess, "run", side_effect=fake_run)
    with pytest.raises(Exception):
        analyzer.run_reachability_analysis(org_slug="my-org", target_directory=".")
    assert calls[0][0] == "npx"
    assert all(c[:2] != ["npm", "install"] for c in calls)


def test_force_npm_install_skips_npx(analyzer, mocker, monkeypatch):
    """SOCKET_CLI_COANA_FORCE_NPM_INSTALL routes straight to npm install + node."""
    monkeypatch.setenv("SOCKET_CLI_COANA_FORCE_NPM_INSTALL", "1")
    calls = _capture_spawns(analyzer, mocker, npx_behavior=0)
    assert all(c[0] != "npx" for c in calls)
    assert calls[0][:2] == ["npm", "install"]
    assert calls[1][0] == "node"


def test_disable_fallback_propagates_npx_failure(analyzer, mocker, monkeypatch):
    """SOCKET_CLI_COANA_DISABLE_NPM_FALLBACK: a launcher failure is NOT retried via npm."""
    monkeypatch.setenv("SOCKET_CLI_COANA_DISABLE_NPM_FALLBACK", "1")
    mocker.patch.object(analyzer, "_extract_scan_id", return_value=None)
    calls = []

    def fake_run(argv, **_kw):
        calls.append(argv)
        m = MagicMock()
        m.returncode = 137
        return m

    mocker.patch.object(reachability.subprocess, "run", side_effect=fake_run)
    with pytest.raises(Exception):
        analyzer.run_reachability_analysis(org_slug="my-org", target_directory=".")
    assert all(c[:2] != ["npm", "install"] for c in calls)
