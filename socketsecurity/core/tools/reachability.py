from socketdev import socketdev
from typing import List, Optional, Dict, Any, Final
import atexit
import os
import platform
import shutil
import subprocess
import json
import pathlib
import logging
import sys
import tempfile

from socketsecurity import __version__

log = logging.getLogger(__name__)

# Pinned @coana-tech/cli version. Bumped deliberately per Python CLI release so the
# reachability engine version only changes through a standard pip upgrade (advance notice).
# Pass --reach-version latest to opt into the newest published version instead.
DEFAULT_COANA_CLI_VERSION: Final = "15.6.5"

# Resolved @coana-tech/cli script paths from the npm-install fallback, keyed by version.
# Lives for the process lifetime so repeated fallback invocations install only once
# (mirrors the Node CLI's installedCoanaScriptPathsByVersion).
_INSTALLED_COANA_SCRIPT_PATHS: Dict[str, str] = {}

# Temp dirs created by the npm-install fallback, removed at process exit.
_COANA_INSTALL_DIRS: List[str] = []


@atexit.register
def _cleanup_coana_install_dirs() -> None:
    for install_dir in _COANA_INSTALL_DIRS:
        shutil.rmtree(install_dir, ignore_errors=True)


def _build_caller_user_agent() -> str:
    """Build the SOCKET_CALLER_USER_AGENT string forwarded to the coana CLI.

    Mirrors the Node CLI's ``<product>/<version> <runtime>/<version> <platform>/<arch>``
    shape so the backend can attribute reachability calls to the Python CLI.
    """
    return (
        f"socket/{__version__} "
        f"python/{platform.python_version()} "
        f"{platform.system().lower()}/{platform.machine().lower()}"
    )


class ReachabilityAnalyzer:
    def __init__(self, sdk: socketdev, api_token: str):
        self.sdk = sdk
        self.api_token = api_token
    
    def _resolve_coana_package_spec(self, version: Optional[str] = None) -> str:
        """
        Resolve the @coana-tech/cli package spec to run (e.g. '@coana-tech/cli@15.6.5').

        Args:
            version: Coana CLI version to use.
                - None: the pinned ``DEFAULT_COANA_CLI_VERSION`` (no auto-update).
                - 'latest': always the newest published version (opt-in to auto-update).
                - '<semver>': that exact version.

        Returns:
            str: The package specifier to use with npx (e.g. '@coana-tech/cli@15.6.5').
        """
        return f"@coana-tech/cli@{self._resolve_coana_version(version)}"

    def _resolve_coana_version(self, version: Optional[str] = None) -> str:
        """Resolve the effective @coana-tech/cli version string (see _resolve_coana_package_spec)."""
        return (version or DEFAULT_COANA_CLI_VERSION).strip()

    
    def run_reachability_analysis(
        self,
        org_slug: str,
        target_directory: str,
        tar_hash: Optional[str] = None,
        output_path: str = ".socket.facts.json",
        timeout: Optional[str] = None,
        memory_limit: Optional[str] = None,
        ecosystems: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        min_severity: Optional[str] = None,
        skip_cache: bool = False,
        disable_analytics: bool = False,
        enable_analysis_splitting: bool = False,
        detailed_analysis_log_file: bool = False,
        lazy_mode: bool = False,
        repo_name: Optional[str] = None,
        branch_name: Optional[str] = None,
        version: Optional[str] = None,
        concurrency: Optional[int] = None,
        additional_params: Optional[List[str]] = None,
        allow_unverified: bool = False,
        enable_debug: bool = False,
        use_only_pregenerated_sboms: bool = False,
        continue_on_analysis_errors: bool = False,
        continue_on_install_errors: bool = False,
        continue_on_missing_lock_files: bool = False,
        continue_on_no_source_files: bool = False,
        reach_debug: bool = False,
        disable_external_tool_checks: bool = False,
    ) -> Dict[str, Any]:
        """
        Run reachability analysis.

        Args:
            org_slug: Socket organization slug
            target_directory: Directory to analyze
            tar_hash: Tar hash from manifest upload or existing scan (optional)
            output_path: Output file path for results
            timeout: Analysis timeout, forwarded verbatim to coana --analysis-timeout
                (coana parses the units, e.g. '90s', '10m', '1h'; a bare number is seconds)
            memory_limit: Memory limit, forwarded verbatim to coana --memory-limit
                (coana parses the units, e.g. '512MB', '8GB'; a bare number is MB)
            ecosystems: List of ecosystems to analyze (e.g., ['npm', 'pypi'])
            exclude_paths: Paths to exclude from analysis
            min_severity: Minimum severity level (info, low, moderate, high, critical)
            skip_cache: Skip cache usage
            disable_analytics: Disable analytics sharing
            enable_analysis_splitting: Enable analysis splitting (disabled by default)
            detailed_analysis_log_file: Print detailed analysis log file path
            lazy_mode: Enable lazy mode for analysis
            repo_name: Repository name
            branch_name: Branch name
            version: @coana-tech/cli version to use. None uses the pinned
                DEFAULT_COANA_CLI_VERSION (no auto-update); 'latest' opts into the newest
                published version; '<semver>' pins an explicit version.
            concurrency: Concurrency level for analysis (must be >= 1)
            additional_params: Additional parameters to pass to coana CLI
            allow_unverified: Disable SSL certificate verification (sets NODE_TLS_REJECT_UNAUTHORIZED=0)
            enable_debug: Enable debug mode (passes -d flag to coana CLI)
            use_only_pregenerated_sboms: Use only pre-generated CDX and SPDX files for the scan

        Returns:
            Dict containing scan_id and report_path
        """
        # Build the coana CLI arguments (everything after the package spec). The launcher
        # (npx, or the npm-install + node fallback) is chosen in _spawn_coana() below.
        coana_args = ["run", "."]

        # Add required arguments
        output_dir = str(pathlib.Path(output_path).parent)
        log.debug(f"output_dir: {output_dir}, output_path: {output_path}")
        coana_args.extend([
            "--output-dir", output_dir,
            "--socket-mode", output_path,
            "--disable-report-submission"
        ])
        
        # Add conditional arguments. timeout/memory_limit are forwarded verbatim; coana owns
        # unit parsing/validation (e.g. '90s', '8GB'). We coerce to str only for subprocess
        # safety — config-file values can arrive as ints via argparse set_defaults — and use
        # `is not None` (not truthiness) so an explicit empty string still reaches coana and
        # triggers coana's own error, rather than being silently dropped.
        if timeout is not None:
            coana_args.extend(["--analysis-timeout", str(timeout)])

        if memory_limit is not None:
            coana_args.extend(["--memory-limit", str(memory_limit)])
        
        if disable_analytics:
            coana_args.append("--disable-analytics-sharing")

        # Analysis splitting is disabled by default; only omit the flag if explicitly enabled
        if not enable_analysis_splitting:
            coana_args.append("--disable-analysis-splitting")

        if detailed_analysis_log_file:
            coana_args.append("--print-analysis-log-file")

        if lazy_mode:
            coana_args.append("--lazy-mode")
        
        # KEY POINT: Only add manifest tar hash if we have one
        if tar_hash:
            coana_args.extend(["--run-without-docker", "--manifests-tar-hash", tar_hash])
        
        if ecosystems:
            coana_args.extend(["--purl-types"] + ecosystems)
        
        if exclude_paths:
            coana_args.extend(["--exclude-dirs"] + exclude_paths)
        
        if min_severity:
            coana_args.extend(["--min-severity", min_severity])
        
        if skip_cache:
            coana_args.append("--skip-cache-usage")
        
        if concurrency:
            coana_args.extend(["--concurrency", str(concurrency)])
        
        if enable_debug:
            coana_args.append("-d")

        if reach_debug:
            coana_args.append("--debug")

        if disable_external_tool_checks:
            coana_args.append("--disable-external-tool-checks")

        if use_only_pregenerated_sboms:
            coana_args.append("--use-only-pregenerated-sboms")

        if continue_on_analysis_errors:
            coana_args.append("--reach-continue-on-analysis-errors")

        if continue_on_install_errors:
            coana_args.append("--reach-continue-on-install-errors")

        if continue_on_missing_lock_files:
            coana_args.append("--reach-continue-on-missing-lock-files")

        if continue_on_no_source_files:
            coana_args.append("--reach-continue-on-no-source-files")

        # Add any additional parameters provided by the user
        if additional_params:
            coana_args.extend(additional_params)
        
        # Set up environment variables
        env = os.environ.copy()
        
        # Required environment variables for Coana CLI
        env["SOCKET_ORG_SLUG"] = org_slug
        env["SOCKET_CLI_API_TOKEN"] = self.api_token

        # Identify the calling CLI to the coana tool / backend (parity with the Node CLI).
        env["SOCKET_CLI_VERSION"] = __version__
        env["SOCKET_CALLER_USER_AGENT"] = _build_caller_user_agent()

        # NOTE: no proxy env is set here. coana already reads HTTPS_PROXY/HTTP_PROXY itself, and
        # we pass the full parent env above, so it inherits them. A SOCKET_CLI_API_PROXY override
        # should only be set from an explicit --proxy flag (not yet implemented), since seeding it
        # from HTTPS_PROXY would be a no-op (it's the same value coana already resolves).

        # Optional environment variables.
        # NOTE: repo/branch are intentionally omitted by the caller (passed as None) when they
        # are the default sentinels, to avoid polluting coana's per-repo/branch cache buckets.
        if repo_name:
            env["SOCKET_REPO_NAME"] = repo_name

        if branch_name:
            env["SOCKET_BRANCH_NAME"] = branch_name

        # Set NODE_TLS_REJECT_UNAUTHORIZED=0 if allow_unverified is True
        if allow_unverified:
            env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        
        # Execute coana
        log.info("Running reachability analysis...")
        log.debug(f"Environment: SOCKET_ORG_SLUG={org_slug}, SOCKET_REPO_NAME={repo_name or 'not set'}, SOCKET_BRANCH_NAME={branch_name or 'not set'}")

        try:
            # Prefer npx (with caching disabled); fall back to `npm install` + `node`
            # if the npx launcher fails before coana starts (parity with the Node CLI).
            returncode = self._spawn_coana(coana_args, version, env, target_directory)

            if returncode != 0:
                log.error(f"Reachability analysis failed with exit code {returncode}")
                raise Exception(f"Reachability analysis failed with exit code {returncode}")
            
            # Extract scan ID from output file
            scan_id = self._extract_scan_id(output_path)
            
            log.info(f"Reachability analysis completed successfully")
            if scan_id:
                log.info(f"Scan ID: {scan_id}")
            
            return {
                "scan_id": scan_id,
                "report_path": output_path,
                "tar_hash_used": tar_hash
            }
        
        except Exception as e:
            log.error(f"Failed to run reachability analysis: {str(e)}")
            raise Exception(f"Failed to run reachability analysis: {str(e)}")

    @staticmethod
    def _sanitize_coana_env(env: Dict[str, str]) -> Dict[str, str]:
        """Drop npm-injected ``npm_package_*`` vars before spawning coana.

        npm/pnpm/yarn populate one env var per leaf of the cwd's package.json
        (``npm_package_dependencies_*`` etc.). In large monorepos this can be tens of KB
        and push argv+env past the OS ARG_MAX, making the spawn fail with E2BIG before
        coana even starts. coana doesn't read these, so dropping them is safe; we keep
        ``npm_config_*`` (registry/cache/proxy) untouched. Mirrors the Node CLI.
        """
        return {k: v for k, v in env.items() if not k.startswith("npm_package_")}

    @staticmethod
    def _npx_launcher_failed_before_coana(returncode: int) -> bool:
        """Heuristic: did npx fail *before* coana started (so retrying is worthwhile)?

        We stream coana's output (no capture), so we classify by exit code alone, like the
        Node CLI does with inherited stdio: signal kills (negative codes) and codes >= 128
        are conventionally launcher/signal failures -> retry. Small positive codes (1..127)
        are ambiguous (coana's own exit codes are small ints), so we do NOT retry.
        """
        return returncode < 0 or returncode >= 128

    @staticmethod
    def _resolve_coana_launcher_mode() -> str:
        """Resolve the coana launcher mode: ``auto``, ``npx``, or ``npm-install``.

        ``SOCKET_CLI_COANA_LAUNCHER`` wins when set to a recognized value; an unrecognized
        value warns and behaves as ``auto``. Only when it is unset/empty do the legacy vars
        apply: ``SOCKET_CLI_COANA_FORCE_NPM_INSTALL`` -> ``npm-install``, else
        ``SOCKET_CLI_COANA_DISABLE_NPM_FALLBACK`` -> ``npx``. Mirrors the Node CLI.
        """
        raw = os.environ.get("SOCKET_CLI_COANA_LAUNCHER", "")
        mode = raw.strip().lower()
        if mode in ("auto", "npx", "npm-install"):
            return mode
        if mode:
            log.warning(
                f'Ignoring unrecognized SOCKET_CLI_COANA_LAUNCHER value "{raw}"; '
                'expected "auto", "npm-install", or "npx".'
            )
            return "auto"
        if os.environ.get("SOCKET_CLI_COANA_FORCE_NPM_INSTALL"):
            return "npm-install"
        if os.environ.get("SOCKET_CLI_COANA_DISABLE_NPM_FALLBACK"):
            return "npx"
        return "auto"

    def _spawn_coana(
        self,
        coana_args: List[str],
        version: Optional[str],
        env: Dict[str, str],
        cwd: str,
    ) -> int:
        """Run coana for the given args, returning the process exit code.

        We run a pinned, versioned spec via npx and intentionally do NOT ``npm install -g``:
        that would silently auto-update the engine on every run and mutate the user's global
        install. The pinned version rides with the Python CLI release instead (see
        ``DEFAULT_COANA_CLI_VERSION``).

        Primary path: ``npx --yes --force @coana-tech/cli@<version> ...`` — the exact flags the
        Socket Node CLI passes for coana (``--yes`` skips npx's interactive install prompt so
        CI runs don't hang).

        Fallback path: if npx is missing, or its launcher dies before coana starts, install
        @coana-tech/cli into a temp dir via ``npm install`` and run it directly via ``node``.
        Tune with ``SOCKET_CLI_COANA_LAUNCHER``: ``auto`` (default; npx with the npm-install
        fallback), ``npm-install`` (skip npx, always use the fallback path), or ``npx``
        (never fall back).
        """
        effective_version = self._resolve_coana_version(version)
        coana_env = self._sanitize_coana_env(env)
        launcher_mode = self._resolve_coana_launcher_mode()

        if launcher_mode == "npm-install":
            return self._spawn_coana_via_npm_install(coana_args, effective_version, coana_env, cwd)

        package_spec = f"@coana-tech/cli@{effective_version}"
        npx_cmd = ["npx", "--yes", "--force", package_spec, *coana_args]
        log.debug(f"Reachability command: {' '.join(npx_cmd)}")
        try:
            result = subprocess.run(
                npx_cmd,
                env=coana_env,
                cwd=cwd,
                stdout=sys.stderr,  # Send stdout to stderr so the user sees it
                stderr=sys.stderr,
            )
        except FileNotFoundError:
            # npx is not on PATH: the launcher provably never started coana.
            if launcher_mode == "npx":
                raise
            log.warning("npx not found on PATH; retrying reachability analysis via `npm install` + `node`.")
            return self._spawn_coana_via_npm_install(coana_args, effective_version, coana_env, cwd)

        if result.returncode == 0:
            return 0

        if launcher_mode != "npx" and self._npx_launcher_failed_before_coana(result.returncode):
            log.warning(
                f"npx launcher failed (exit {result.returncode}) before coana started; "
                "retrying reachability analysis via `npm install` + `node`."
            )
            return self._spawn_coana_via_npm_install(coana_args, effective_version, coana_env, cwd)

        return result.returncode

    def _spawn_coana_via_npm_install(
        self,
        coana_args: List[str],
        version: str,
        env: Dict[str, str],
        cwd: str,
    ) -> int:
        """Fallback launcher: ``npm install`` @coana-tech/cli into a temp dir, run via ``node``.

        Used when npx is unavailable or its launcher fails before coana boots. Mirrors the
        Node CLI's npm-install fallback. Returns coana's exit code; raises if the install
        itself fails or if ``node`` is unavailable.
        """
        script_path = self._install_coana_to_tmpdir(version, env)
        node_cmd = self._build_coana_node_cmd(script_path, coana_args)
        log.debug(f"Reachability fallback command: {' '.join(node_cmd)}")
        try:
            result = subprocess.run(node_cmd, env=env, cwd=cwd, stdout=sys.stderr, stderr=sys.stderr)
        except FileNotFoundError as e:
            # The fallback exists for broken-launcher environments, but it still needs node.
            raise Exception(
                "`node` was not found on PATH; it is required to run the reachability engine "
                "via the npm-install fallback."
            ) from e
        return result.returncode

    def _install_coana_to_tmpdir(self, version: str, env: Dict[str, str]) -> str:
        """``npm install`` @coana-tech/cli@<version> into a temp dir; return its executable JS path.

        Caches the resolved path per version for the process lifetime so repeated fallback
        invocations install only once (mirrors the Node CLI's installCoanaToTmpdir). Raises if
        the install fails.
        """
        cached = _INSTALLED_COANA_SCRIPT_PATHS.get(version)
        if cached and os.path.exists(cached):
            return cached

        install_dir = tempfile.mkdtemp(prefix="socket-coana-")
        _COANA_INSTALL_DIRS.append(install_dir)
        npm_cmd = [
            "npm", "install",
            "--no-save", "--no-package-lock", "--no-audit", "--no-fund",
            "--prefix", install_dir,
            f"@coana-tech/cli@{version}",
        ]
        log.info("Installing reachability analysis engine via npm fallback...")
        log.debug(f"npm install fallback command: {' '.join(npm_cmd)}")
        install = subprocess.run(npm_cmd, env=env, stdout=sys.stderr, stderr=sys.stderr)
        if install.returncode != 0:
            raise Exception(
                f"npm install fallback for @coana-tech/cli@{version} failed with exit code {install.returncode}"
            )

        script_path = self._resolve_coana_bin(install_dir)
        _INSTALLED_COANA_SCRIPT_PATHS[version] = script_path
        return script_path

    @staticmethod
    def _resolve_coana_bin(install_dir: str) -> str:
        """Resolve @coana-tech/cli's executable JS from its installed package.json ``bin`` field."""
        package_json_path = os.path.join(
            install_dir, "node_modules", "@coana-tech", "cli", "package.json"
        )
        with open(package_json_path, "r") as f:
            pkg = json.load(f)
        bin_field = pkg.get("bin")
        relative_bin = None
        if isinstance(bin_field, str):
            relative_bin = bin_field
        elif isinstance(bin_field, dict):
            # Prefer an entry named "coana"; otherwise take the first.
            relative_bin = bin_field.get("coana") or next(iter(bin_field.values()), None)
        if not relative_bin:
            raise Exception(
                f"@coana-tech/cli package.json at {package_json_path} is missing a usable bin entry"
            )
        return os.path.abspath(os.path.join(os.path.dirname(package_json_path), relative_bin))

    @staticmethod
    def _build_coana_node_cmd(script_path: str, coana_args: List[str]) -> List[str]:
        """Run a .js/.mjs entry via ``node``; invoke a native binary directly (Node CLI parity)."""
        if script_path.endswith(".js") or script_path.endswith(".mjs"):
            return ["node", script_path, *coana_args]
        return [script_path, *coana_args]

    def _extract_scan_id(self, facts_file_path: str) -> Optional[str]:
        """
        Extract tier1ReachabilityScanId from the socket facts JSON file.
        
        Args:
            facts_file_path: Path to the .socket.facts.json file
            
        Returns:
            Optional[str]: The scan ID if found, None otherwise
        """
        try:
            if not os.path.exists(facts_file_path):
                log.warning(f"Facts file not found: {facts_file_path}")
                return None
            
            with open(facts_file_path, 'r') as f:
                facts = json.load(f)
            
            scan_id = facts.get('tier1ReachabilityScanId')
            return scan_id.strip() if scan_id else None
        
        except (json.JSONDecodeError, IOError) as e:
            log.warning(f"Failed to extract scan ID from {facts_file_path}: {e}")
            return None
