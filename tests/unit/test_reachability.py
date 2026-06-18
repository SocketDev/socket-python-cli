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


@pytest.fixture(autouse=True)
def _clear_coana_install_cache():
    """The npm-install fallback caches resolved script paths in a module-level dict; isolate tests."""
    reachability._INSTALLED_COANA_SCRIPT_PATHS.clear()
    try:
        yield
    finally:
        reachability._INSTALLED_COANA_SCRIPT_PATHS.clear()


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
    cmd, _ = _run(analyzer, mocker, concurrency=1, memory_limit="8192")
    assert "--concurrency" in cmd and cmd[cmd.index("--concurrency") + 1] == "1"
    assert "--memory-limit" in cmd and cmd[cmd.index("--memory-limit") + 1] == "8192"


def test_timeout_and_memory_units_forwarded_verbatim(analyzer, mocker):
    """Unit-bearing timeout/memory strings are forwarded to coana untouched (coana parses them)."""
    cmd, _ = _run(analyzer, mocker, timeout="10m", memory_limit="8GB")
    assert cmd[cmd.index("--analysis-timeout") + 1] == "10m"
    assert cmd[cmd.index("--memory-limit") + 1] == "8GB"


def test_timeout_and_memory_int_values_coerced_to_str(analyzer, mocker):
    """Config-file values can arrive as ints (set_defaults bypasses argparse type=); they must
    still reach subprocess as strings, not raw ints."""
    cmd, _ = _run(analyzer, mocker, timeout=300, memory_limit=2048)
    assert cmd[cmd.index("--analysis-timeout") + 1] == "300"
    assert cmd[cmd.index("--memory-limit") + 1] == "2048"


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


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        # No --reach-version -> pinned default (no auto-update).
        (None, f"@coana-tech/cli@{DEFAULT_COANA_CLI_VERSION}"),
        # Explicit version pinned through.
        ("1.2.3", "@coana-tech/cli@1.2.3"),
        # 'latest' opts into the newest published version.
        ("latest", "@coana-tech/cli@latest"),
        # Surrounding whitespace is stripped; always versioned (never bare '@coana-tech/cli').
        (" 1.2.3 ", "@coana-tech/cli@1.2.3"),
    ],
)
def test_resolve_coana_package_spec(analyzer, version, expected):
    assert analyzer._resolve_coana_package_spec(version) == expected


def _spec_in(cmd):
    """The @coana-tech/cli@<version> spec from an npx argv (it follows the npx flags)."""
    return next(a for a in cmd if a.startswith("@coana-tech/cli@"))


def test_npx_uses_yes_and_force_flags(analyzer, mocker):
    """npx is invoked with --yes --force — the exact flags the Node CLI passes for coana."""
    cmd, _ = _run(analyzer, mocker)
    assert cmd[0] == "npx"
    assert "--yes" in cmd
    assert "--force" in cmd


@pytest.mark.parametrize(
    ("version", "expected_spec"),
    [
        (None, f"@coana-tech/cli@{DEFAULT_COANA_CLI_VERSION}"),  # pinned default
        ("9.9.9", "@coana-tech/cli@9.9.9"),                     # explicit pin
        ("latest", "@coana-tech/cli@latest"),                  # opt-in to newest
    ],
)
def test_npx_runs_resolved_version(analyzer, mocker, version, expected_spec):
    cmd, _ = _run(analyzer, mocker, version=version)
    assert _spec_in(cmd) == expected_spec


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


@pytest.mark.parametrize(
    ("returncode", "is_launcher_failure"),
    [
        # Signal kills / >=128 -> launcher failure -> retry.
        (-9, True),    # killed by signal
        (137, True),   # 128 + SIGKILL
        (249, True),   # observed npx launcher failure
        # Small positive exit codes are ambiguous (coana's own codes) -> do NOT retry.
        (1, False),
        (2, False),
        (127, False),
    ],
)
def test_launcher_failure_heuristic(returncode, is_launcher_failure):
    f = ReachabilityAnalyzer._npx_launcher_failed_before_coana
    assert f(returncode) is is_launcher_failure


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


def test_fallback_installs_once_per_version(analyzer, mocker):
    """A second in-process fallback for the same version reuses the install (no re-install)."""
    mocker.patch.object(analyzer, "_extract_scan_id", return_value="scan-123")
    mocker.patch.object(reachability.tempfile, "mkdtemp", return_value="/tmp/socket-coana-cache")
    mocker.patch.object(
        analyzer,
        "_resolve_coana_bin",
        return_value="/tmp/socket-coana-cache/node_modules/@coana-tech/cli/coana.js",
    )
    # The cached script path must "exist" for the 2nd run to reuse it.
    mocker.patch.object(reachability.os.path, "exists", return_value=True)
    calls = []

    def fake_run(argv, **_kw):
        calls.append(argv)
        m = MagicMock()
        m.returncode = 137 if argv[0] == "npx" else 0
        return m

    mocker.patch.object(reachability.subprocess, "run", side_effect=fake_run)
    analyzer.run_reachability_analysis(org_slug="my-org", target_directory=".")
    analyzer.run_reachability_analysis(org_slug="my-org", target_directory=".")

    npm_installs = [c for c in calls if c[:2] == ["npm", "install"]]
    assert len(npm_installs) == 1  # installed once, reused on the second fallback


def test_fallback_node_missing_raises_clear_error(analyzer, mocker):
    """If `node` is missing in the fallback, surface a clear error (not opaque FileNotFoundError)."""
    mocker.patch.object(analyzer, "_extract_scan_id", return_value=None)
    mocker.patch.object(reachability.tempfile, "mkdtemp", return_value="/tmp/socket-coana-n")
    mocker.patch.object(
        analyzer,
        "_resolve_coana_bin",
        return_value="/tmp/socket-coana-n/node_modules/@coana-tech/cli/coana.js",
    )

    def fake_run(argv, **_kw):
        if argv[0] == "npx":
            m = MagicMock()
            m.returncode = 137
            return m
        if argv[0] == "node":
            raise FileNotFoundError("node")
        m = MagicMock()  # npm install succeeds
        m.returncode = 0
        return m

    mocker.patch.object(reachability.subprocess, "run", side_effect=fake_run)
    with pytest.raises(Exception, match="node"):
        analyzer.run_reachability_analysis(org_slug="my-org", target_directory=".")


def test_build_coana_node_cmd_js_vs_binary():
    f = ReachabilityAnalyzer._build_coana_node_cmd
    assert f("/x/coana.js", ["run", "."]) == ["node", "/x/coana.js", "run", "."]
    assert f("/x/coana.mjs", ["run"]) == ["node", "/x/coana.mjs", "run"]
    assert f("/x/coana", ["run", "."]) == ["/x/coana", "run", "."]


def test_resolve_coana_bin_parses_package_json(analyzer, tmp_path):
    pkg_dir = tmp_path / "node_modules" / "@coana-tech" / "cli"
    pkg_dir.mkdir(parents=True)

    # string bin
    (pkg_dir / "package.json").write_text('{"bin": "dist/coana.js"}')
    assert analyzer._resolve_coana_bin(str(tmp_path)) == str(pkg_dir / "dist" / "coana.js")

    # dict bin, prefer the "coana" entry
    (pkg_dir / "package.json").write_text('{"bin": {"coana": "dist/c.js", "other": "x.js"}}')
    assert analyzer._resolve_coana_bin(str(tmp_path)) == str(pkg_dir / "dist" / "c.js")

    # dict bin without "coana" -> first value
    (pkg_dir / "package.json").write_text('{"bin": {"other": "x.js"}}')
    assert analyzer._resolve_coana_bin(str(tmp_path)) == str(pkg_dir / "x.js")

    # missing bin -> raises
    (pkg_dir / "package.json").write_text("{}")
    with pytest.raises(Exception, match="bin"):
        analyzer._resolve_coana_bin(str(tmp_path))
