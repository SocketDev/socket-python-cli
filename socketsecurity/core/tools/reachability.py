from socketdev import socketdev
from typing import List, Optional, Dict, Any
import os
import platform
import subprocess
import json
import pathlib
import logging
import sys

from socketsecurity import __version__

log = logging.getLogger(__name__)

# Pinned @coana-tech/cli version. Bumped deliberately per Python CLI release so the
# reachability engine version only changes through a standard pip upgrade (advance notice).
# Pass --reach-version latest to opt into the newest published version instead.
DEFAULT_COANA_CLI_VERSION = "15.3.22"


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
        Resolve the @coana-tech/cli package spec to run with npx.

        We pass an exact, versioned spec to npx so it runs a deterministic version from its
        own cache (fetching once if absent). We intentionally do NOT ``npm install -g`` here:
        that would silently auto-update the engine on every run and mutate the user's global
        install. The pinned version rides with the Python CLI release instead, so engine
        changes only happen through a standard pip upgrade (advance notice).

        Args:
            version: Coana CLI version to use.
                - None: the pinned ``DEFAULT_COANA_CLI_VERSION`` (no auto-update).
                - 'latest': always the newest published version (opt-in to auto-update).
                - '<semver>': that exact version.

        Returns:
            str: The package specifier to use with npx (e.g. '@coana-tech/cli@15.3.22').
        """
        effective = (version or DEFAULT_COANA_CLI_VERSION).strip()
        return f"@coana-tech/cli@{effective}"

    
    def run_reachability_analysis(
        self,
        org_slug: str,
        target_directory: str,
        tar_hash: Optional[str] = None,
        output_path: str = ".socket.facts.json",
        timeout: Optional[int] = None,
        memory_limit: Optional[int] = None,
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
            timeout: Analysis timeout in seconds
            memory_limit: Memory limit in MB
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
        # Resolve the pinned (or explicitly requested) @coana-tech/cli version for npx
        cli_package = self._resolve_coana_package_spec(version)
        
        # Build CLI command arguments
        cmd = ["npx", cli_package, "run", "."]
        
        # Add required arguments
        output_dir = str(pathlib.Path(output_path).parent)
        log.debug(f"output_dir: {output_dir}, output_path: {output_path}")
        cmd.extend([
            "--output-dir", output_dir,
            "--socket-mode", output_path,
            "--disable-report-submission"
        ])
        
        # Add conditional arguments
        if timeout:
            cmd.extend(["--analysis-timeout", str(timeout)])
        
        if memory_limit:
            cmd.extend(["--memory-limit", str(memory_limit)])
        
        if disable_analytics:
            cmd.append("--disable-analytics-sharing")

        # Analysis splitting is disabled by default; only omit the flag if explicitly enabled
        if not enable_analysis_splitting:
            cmd.append("--disable-analysis-splitting")

        if detailed_analysis_log_file:
            cmd.append("--print-analysis-log-file")

        if lazy_mode:
            cmd.append("--lazy-mode")
        
        # KEY POINT: Only add manifest tar hash if we have one
        if tar_hash:
            cmd.extend(["--run-without-docker", "--manifests-tar-hash", tar_hash])
        
        if ecosystems:
            cmd.extend(["--purl-types"] + ecosystems)
        
        if exclude_paths:
            cmd.extend(["--exclude-dirs"] + exclude_paths)
        
        if min_severity:
            cmd.extend(["--min-severity", min_severity])
        
        if skip_cache:
            cmd.append("--skip-cache-usage")
        
        if concurrency:
            cmd.extend(["--concurrency", str(concurrency)])
        
        if enable_debug:
            cmd.append("-d")

        if reach_debug:
            cmd.append("--debug")

        if disable_external_tool_checks:
            cmd.append("--disable-external-tool-checks")

        if use_only_pregenerated_sboms:
            cmd.append("--use-only-pregenerated-sboms")

        if continue_on_analysis_errors:
            cmd.append("--reach-continue-on-analysis-errors")

        if continue_on_install_errors:
            cmd.append("--reach-continue-on-install-errors")

        if continue_on_missing_lock_files:
            cmd.append("--reach-continue-on-missing-lock-files")

        if continue_on_no_source_files:
            cmd.append("--reach-continue-on-no-source-files")

        # Add any additional parameters provided by the user
        if additional_params:
            cmd.extend(additional_params)
        
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
        
        # Execute CLI
        log.info("Running reachability analysis...")
        log.debug(f"Reachability command: {' '.join(cmd)}")
        log.debug(f"Environment: SOCKET_ORG_SLUG={org_slug}, SOCKET_REPO_NAME={repo_name or 'not set'}, SOCKET_BRANCH_NAME={branch_name or 'not set'}")
        
        try:
            # Run with output streaming to stderr (don't capture output)
            result = subprocess.run(
                cmd,
                env=env,
                cwd=target_directory,
                stdout=sys.stderr,  # Send stdout to stderr so user sees it
                stderr=sys.stderr,  # Send stderr to stderr
            )
            
            if result.returncode != 0:
                log.error(f"Reachability analysis failed with exit code {result.returncode}")
                raise Exception(f"Reachability analysis failed with exit code {result.returncode}")
            
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
