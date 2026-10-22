"""Tests for launching the Coana CLI from ReachabilityAnalyzer.

A fake cli-wrapper.mjs is installed into a temporary cache with the real coana-cache.mjs, so
nothing is mocked. The fake records the args, cwd and environment it was run with.
"""
import json
import os
import subprocess

import pytest

from socketsecurity import __version__
from socketsecurity.core.cli_client import CliClient
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.core.tools import reachability
from socketsecurity.core.tools.reachability import (
    ReachabilityAnalyzer,
    _build_caller_user_agent,
)

VERSION = "1.2.3"

# Records what it was run with in $FAKE_COANA_RUN, or fails when passed --fail. Like Coana, it
# writes the facts file to the --socket-mode path, resolved against its cwd.
FAKE_CLI_WRAPPER = """
import { writeFileSync } from 'node:fs'
const args = process.argv.slice(2)
if (args.includes('--fail')) process.exit(1)
writeFileSync(process.env.FAKE_COANA_RUN, JSON.stringify({ args, cwd: process.cwd(), env: process.env }))
writeFileSync(args[args.indexOf('--socket-mode') + 1], JSON.stringify({ tier1ReachabilityScanId: 'reach-scan-id' }))
"""


@pytest.fixture(scope="module")
def cache_home(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("coana")
    extracted = tmp / "extracted"
    extracted.mkdir()
    (extracted / "cli-wrapper.mjs").write_text(FAKE_CLI_WRAPPER)
    subprocess.run(
        ["node", str(reachability._COANA_CACHE_SCRIPT), "install", VERSION, "cli", "a" * 64, str(extracted)],
        env={**os.environ, "XDG_CACHE_HOME": str(tmp / "cache")},
        check=True,
        capture_output=True,
    )
    return tmp / "cache"


@pytest.fixture
def fake_run_path(tmp_path, monkeypatch, cache_home):
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache_home))
    path = tmp_path / "run.json"
    monkeypatch.setenv("FAKE_COANA_RUN", str(path))
    return path


def _analyzer(api_url="https://api.socket.dev/v0"):
    return ReachabilityAnalyzer(CliClient(SocketConfig(api_key="test-api-token", api_url=api_url)))


def _run(fake_run_path, analyzer=None, **kwargs):
    """Run the fake Coana; return the args, cwd and env it recorded."""
    (analyzer or _analyzer()).run_reachability_analysis(
        org_slug="my-org",
        target_directory=str(fake_run_path.parent),
        tar_hash="tar-hash-abc123",
        output_path=str(fake_run_path.parent / ".socket.facts.json"),
        version=VERSION,
        **kwargs,
    )
    return json.loads(fake_run_path.read_text())


def test_build_caller_user_agent_shape():
    ua = _build_caller_user_agent()
    parts = ua.split(" ")
    assert parts[0] == f"socket/{__version__}"
    assert parts[1].startswith("python/")
    assert "/" in parts[2]  # platform/arch


def test_runs_the_cached_cli_wrapper_with_the_args_and_cwd(fake_run_path):
    run = _run(fake_run_path)
    assert run["args"][:2] == ["run", "."]
    assert "--manifests-tar-hash" in run["args"]
    assert run["cwd"] == str(fake_run_path.parent)


@pytest.mark.parametrize("absolute", [False, True])
def test_report_path_is_where_coana_wrote_the_facts_file(fake_run_path, tmp_path, monkeypatch, absolute):
    target = tmp_path / "project"
    target.mkdir()
    monkeypatch.chdir(tmp_path)
    output_path = str(tmp_path / "out" / "facts.json") if absolute else ".socket.facts.json"
    if absolute:
        (tmp_path / "out").mkdir()

    result = _analyzer().run_reachability_analysis(
        org_slug="my-org",
        target_directory=str(target),
        tar_hash="tar-hash-abc123",
        output_path=output_path,
        version=VERSION,
    )

    assert result["report_path"] == (output_path if absolute else str(target / ".socket.facts.json"))
    assert result["scan_id"] == "reach-scan-id"


def test_reach_debug_appends_debug_long_flag(fake_run_path):
    """G9: --reach-debug -> coana --debug; does not emit the global -d."""
    args = _run(fake_run_path, reach_debug=True)["args"]
    assert "--debug" in args
    assert "-d" not in args


def test_enable_debug_still_emits_short_d(fake_run_path):
    """G9: existing global --enable-debug -> -d behavior is unchanged."""
    args = _run(fake_run_path, enable_debug=True)["args"]
    assert "-d" in args
    assert "--debug" not in args


def test_disable_external_tool_checks(fake_run_path):
    """G1: --reach-disable-external-tool-checks -> coana --disable-external-tool-checks."""
    assert "--disable-external-tool-checks" in _run(fake_run_path, disable_external_tool_checks=True)["args"]
    assert "--disable-external-tool-checks" not in _run(fake_run_path)["args"]


def test_timeout_and_memory_forwarded_verbatim(fake_run_path):
    """coana parses the units; config-file ints are coerced to strings."""
    args = _run(fake_run_path, timeout="10m", memory_limit=2048, concurrency=1)["args"]
    assert args[args.index("--analysis-timeout") + 1] == "10m"
    assert args[args.index("--memory-limit") + 1] == "2048"
    assert args[args.index("--concurrency") + 1] == "1"


def test_env_identifies_python_cli(fake_run_path):
    """G5: SOCKET_CLI_VERSION + SOCKET_CALLER_USER_AGENT forwarded to coana."""
    env = _run(fake_run_path)["env"]
    assert env["SOCKET_CLI_VERSION"] == __version__
    assert env["SOCKET_CALLER_USER_AGENT"] == _build_caller_user_agent()
    assert env["SOCKET_ORG_SLUG"] == "my-org"
    assert env["SOCKET_CLI_API_TOKEN"] == "test-api-token"


@pytest.mark.parametrize("api_url", ["https://api.example.test/v0", "https://api.example.test/v0/"])
def test_env_api_base_url_follows_the_client(fake_run_path, api_url):
    env = _run(fake_run_path, analyzer=_analyzer(api_url))["env"]
    assert env["SOCKET_CLI_API_BASE_URL"] == "https://api.example.test/v0/"


def test_no_proxy_env_set_by_default(fake_run_path, monkeypatch):
    """coana reads HTTPS_PROXY/HTTP_PROXY itself; SOCKET_CLI_API_PROXY is reserved for a future
    explicit --proxy flag."""
    monkeypatch.delenv("SOCKET_CLI_API_PROXY", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://envproxy:3128")
    env = _run(fake_run_path)["env"]
    assert env["HTTPS_PROXY"] == "http://envproxy:3128"
    assert "SOCKET_CLI_API_PROXY" not in env


def test_repo_and_branch_env(fake_run_path):
    """G6: caller passes None for default sentinels -> env keys omitted (cache hygiene)."""
    env = _run(fake_run_path, repo_name="acme/widget", branch_name="main")["env"]
    assert env["SOCKET_REPO_NAME"] == "acme/widget"
    assert env["SOCKET_BRANCH_NAME"] == "main"

    env = _run(fake_run_path)["env"]
    assert "SOCKET_REPO_NAME" not in env
    assert "SOCKET_BRANCH_NAME" not in env


def test_env_strips_npm_package_vars(fake_run_path, monkeypatch):
    """npm_package_* dropped (E2BIG guard); npm_config_* kept. Parity with the Node CLI."""
    monkeypatch.setenv("npm_package_dependencies_foo", "1.0.0")
    monkeypatch.setenv("npm_config_registry", "https://example.test")
    env = _run(fake_run_path)["env"]
    assert "npm_package_dependencies_foo" not in env
    assert env["npm_config_registry"] == "https://example.test"


def test_failing_run_raises(fake_run_path):
    with pytest.raises(Exception, match="exit code 1"):
        _run(fake_run_path, additional_params=["--fail"])
