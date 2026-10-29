import hashlib
import json
import logging
import os
import pathlib
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, Final, List, Mapping, Optional

import requests

from socketsecurity import USER_AGENT, __version__
from socketsecurity.core.cli_client import CliClient

log = logging.getLogger(__name__)

# Pinned Coana CLI version. Bumped deliberately per Python CLI release so the
# reachability engine version only changes through a standard pip upgrade (advance notice).
# Pass --reach-version latest to opt into the newest published version instead.
DEFAULT_COANA_CLI_VERSION: Final = "15.13.2"

# Vendored from coana-package-manager, where it is generated; the only code that may read or
# write the cache Coana shares with the Socket CLIs. See "Launching Coana" in that repo's
# packages/cli/docs/gcs-releases.md.
_COANA_CACHE_SCRIPT: Final = pathlib.Path(__file__).with_name("coana-cache.mjs")
_COANA_COMPONENT: Final = "cli"
_NOT_CACHED_EXIT_CODE: Final = 4

_EXACT_VERSION: Final = re.compile(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?")
_SHA256: Final = re.compile(r"[0-9a-f]{64}")
# Seconds to connect to the download host, and seconds it may go without sending a byte.
_DOWNLOAD_TIMEOUT: Final = (30, 60)


@dataclass(frozen=True)
class _CoanaComponent:
    sha256: str
    size: int
    url: str


@dataclass(frozen=True)
class _CoanaArtifacts:
    version: str
    cli: _CoanaComponent

    @classmethod
    def parse(cls, value: object) -> Optional["_CoanaArtifacts"]:
        """Parse the Socket API's response to a request for the ``cli`` component."""
        if not isinstance(value, dict):
            return None
        version = value.get("version")
        components = value.get("components")
        cli = components.get(_COANA_COMPONENT) if isinstance(components, dict) else None
        if not isinstance(cli, dict):
            return None
        sha256, size, url = cli.get("sha256"), cli.get("size"), cli.get("url")
        if (
            not isinstance(version, str)
            or not _EXACT_VERSION.fullmatch(version)
            or not isinstance(sha256, str)
            or not _SHA256.fullmatch(sha256)
            # bool is an int subclass.
            or type(size) is not int
            or size <= 0
            or not isinstance(url, str)
            or not url.startswith("https://")
        ):
            return None
        return cls(version=version, cli=_CoanaComponent(sha256=sha256, size=size, url=url))


class _DownloadRefused(Exception):
    """The download host refused a signed URL with a 4xx, e.g. because it expired."""


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
    def __init__(self, client: CliClient):
        self.client = client

    def run_reachability_analysis(
        self,
        org_slug: str,
        target_directory: str,
        tar_hash: str,
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
        repo_name: Optional[str] = None,
        branch_name: Optional[str] = None,
        version: Optional[str] = None,
        concurrency: Optional[int] = None,
        additional_params: Optional[List[str]] = None,
        enable_debug: bool = False,
        use_only_pregenerated_sboms: bool = False,
        continue_on_analysis_errors: bool = False,
        continue_on_install_errors: bool = False,
        continue_on_missing_lock_files: bool = False,
        continue_on_no_source_files: bool = False,
        reach_debug: bool = False,
        disable_external_tool_checks: bool = False,
        disable_dependency_downloads: bool = False,
    ) -> Dict[str, Any]:
        """
        Run reachability analysis.

        Args:
            org_slug: Socket organization slug
            target_directory: Directory to analyze
            tar_hash: Tar hash from manifest upload or existing scan (optional)
            output_path: Output file path for results, relative to target_directory unless absolute
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
            repo_name: Repository name
            branch_name: Branch name
            version: Coana CLI version spec to use. None uses the pinned
                DEFAULT_COANA_CLI_VERSION (no auto-update); 'latest' opts into the newest
                published version; '<semver>' pins an explicit version.
            concurrency: Concurrency level for analysis (must be >= 1)
            additional_params: Additional parameters to pass to coana CLI
            enable_debug: Enable debug mode (passes -d flag to coana CLI)
            use_only_pregenerated_sboms: Use only pre-generated CDX and SPDX files for the scan

        Returns:
            Dict containing scan_id and report_path
        """
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
        # safety — config-file values can arrive as ints via argparse set_defaults.
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

        if disable_dependency_downloads:
            coana_args.append("--disable-dependency-downloads")

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
        env = self._sanitize_coana_env(os.environ)

        # Required environment variables for Coana CLI
        env["SOCKET_ORG_SLUG"] = org_slug
        env["SOCKET_CLI_API_TOKEN"] = self.client.config.api_key
        # Coana expects the base URL to include the trailing slash after /v0.
        env["SOCKET_CLI_API_BASE_URL"] = self.client.config.api_url.rstrip("/") + "/"

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

        if self.client.config.allow_unverified_ssl:
            env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        
        # Execute coana
        log.info("Running reachability analysis...")
        log.debug(f"Environment: SOCKET_ORG_SLUG={org_slug}, SOCKET_REPO_NAME={repo_name or 'not set'}, SOCKET_BRANCH_NAME={branch_name or 'not set'}")

        try:
            cli_dir = self._get_coana_cli_dir((version or DEFAULT_COANA_CLI_VERSION).strip(), org_slug, env)
            cmd = ["node", os.path.join(cli_dir, "cli-wrapper.mjs"), *coana_args]
            log.debug(f"Reachability command: {' '.join(cmd)}")
            returncode = subprocess.run(
                cmd,
                env=env,
                cwd=target_directory,
                stdout=sys.stderr,  # Send stdout to stderr so the user sees it
                stderr=sys.stderr,
            ).returncode

            if returncode != 0:
                log.error(f"Reachability analysis failed with exit code {returncode}")
                raise Exception(f"Reachability analysis failed with exit code {returncode}")
            
            # Coana runs in target_directory, so a relative output_path lands there.
            report_path = os.path.join(target_directory, output_path)
            scan_id = self._extract_scan_id(report_path)
            
            log.info("Reachability analysis completed successfully")
            if scan_id:
                log.info(f"Scan ID: {scan_id}")
            
            return {
                "scan_id": scan_id,
                "report_path": report_path,
                "tar_hash_used": tar_hash
            }
        
        except Exception as e:
            log.error(f"Failed to run reachability analysis: {str(e)}")
            raise Exception(f"Failed to run reachability analysis: {str(e)}")

    @staticmethod
    def _sanitize_coana_env(env: Mapping[str, str]) -> Dict[str, str]:
        """Drop npm-injected ``npm_package_*`` vars before spawning coana.

        TODO: probably unnecessary. The E2BIG came from npm exec re-adding these vars, and
        coana no longer runs through npm, so its env is only slightly larger than our own.

        npm/pnpm/yarn populate one env var per leaf of the cwd's package.json
        (``npm_package_dependencies_*`` etc.). In large monorepos this can be tens of KB
        and push argv+env past the OS ARG_MAX, making the spawn fail with E2BIG before
        coana even starts. coana doesn't read these, so dropping them is safe; we keep
        ``npm_config_*`` (registry/cache/proxy) untouched. Mirrors the Node CLI.
        """
        return {k: v for k, v in env.items() if not k.startswith("npm_package_")}

    def _get_coana_cli_dir(self, version_spec: str, org_slug: str, env: Dict[str, str]) -> str:
        """The directory of the Coana CLI's ``cli`` component for ``version_spec``.

        ``version_spec`` is an exact version, a range or ``latest``. On a cache miss the
        component is downloaded from the Socket API and installed into the cache. ``env``
        reaches the cache script, which reads ``XDG_CACHE_HOME`` from it.
        """

        def run_coana_cache(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["node", str(_COANA_CACHE_SCRIPT), *args], env=env, capture_output=True, text=True
            )

        def printed_dir(result: subprocess.CompletedProcess[str]) -> str:
            """The directory the cache script printed, which is all it prints to stdout."""
            if result.returncode != 0:
                detail = result.stderr.strip() or f"{_COANA_CACHE_SCRIPT.name} exited with {result.returncode}"
                raise Exception(f"The Coana cache failed: {detail}")
            return result.stdout.strip()

        def lookup(version: str) -> Optional[str]:
            result = run_coana_cache("lookup", version, _COANA_COMPONENT)
            return None if result.returncode == _NOT_CACHED_EXIT_CODE else printed_dir(result)

        def request_artifacts(spec: str) -> _CoanaArtifacts:
            # The API refuses specs it can't serve, with an explanation that APIFailure carries.
            response = self.client.request(
                f"orgs/{org_slug}/coana-cli/artifacts",
                method="POST",
                payload=json.dumps({"version": spec, "components": [_COANA_COMPONENT]}),
            )
            try:
                body = response.json()
            except ValueError:
                body = None
            if (artifacts := _CoanaArtifacts.parse(body)) is None:
                raise Exception(f"Unexpected response from the Socket API to a request for the Coana CLI {spec}")
            return artifacts

        def download(component: _CoanaComponent, dest: pathlib.Path) -> None:
            with requests.get(
                component.url,
                headers={"User-Agent": USER_AGENT},
                stream=True,
                timeout=_DOWNLOAD_TIMEOUT,
                verify=not self.client.config.allow_unverified_ssl,
            ) as response:
                if 400 <= response.status_code < 500:
                    raise _DownloadRefused(
                        f"The download host refused the Coana CLI URL with status {response.status_code}"
                    )
                response.raise_for_status()
                digest = hashlib.sha256()
                received = 0
                with dest.open("wb") as f:
                    # The checksum covers the bytes as stored, so skip any Content-Encoding.
                    for chunk in response.raw.stream(1 << 16, decode_content=False):
                        received += len(chunk)
                        if received > component.size:
                            raise Exception(
                                f"The Coana CLI tarball is larger than the expected {component.size} bytes"
                            )
                        digest.update(chunk)
                        f.write(chunk)
            sha256 = digest.hexdigest()
            if received != component.size or sha256 != component.sha256:
                raise Exception(
                    "The Coana CLI tarball does not match its checksum "
                    f"(expected {component.size} bytes with sha256 {component.sha256}, "
                    f"got {received} bytes with sha256 {sha256})"
                )

        def regular_files_only(member: tarfile.TarInfo, path: str) -> Optional[tarfile.TarInfo]:
            return tarfile.data_filter(member, path) if member.isfile() or member.isdir() else None

        if _EXACT_VERSION.fullmatch(version_spec) and (cached := lookup(version_spec)):
            return cached
        artifacts = request_artifacts(version_spec)
        if artifacts.version != version_spec and (cached := lookup(artifacts.version)):
            return cached

        log.info(f"Downloading the Coana CLI {artifacts.version}...")
        with tempfile.TemporaryDirectory(prefix="socket-coana-cli-") as tmp:
            tarball = pathlib.Path(tmp, "cli.tar.gz")
            try:
                download(artifacts.cli, tarball)
            except _DownloadRefused:
                # Pin the new request to the resolved version, which a range is not.
                artifacts = request_artifacts(artifacts.version)
                download(artifacts.cli, tarball)
            extract_dir = pathlib.Path(tmp, "cli")
            with tarfile.open(tarball, "r:gz") as archive:
                # Without extraction filters, the checked sha256 vouches for the tarball.
                archive.extractall(
                    extract_dir, **({"filter": regular_files_only} if hasattr(tarfile, "data_filter") else {})
                )
            return printed_dir(
                run_coana_cache("install", artifacts.version, _COANA_COMPONENT, artifacts.cli.sha256, str(extract_dir))
            )

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
