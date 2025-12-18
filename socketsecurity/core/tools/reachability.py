from socketdev import socketdev
from typing import List, Optional, Dict, Any
import os
import subprocess
import json
import pathlib
import logging
import sys

log = logging.getLogger(__name__)


class ReachabilityAnalyzer:
    def __init__(self, sdk: socketdev, api_token: str):
        self.sdk = sdk
        self.api_token = api_token
    
    def _ensure_coana_cli_installed(self, version: Optional[str] = None) -> str:
        """
        Check if @coana-tech/cli is installed, and install/update it if needed.
        
        Args:
            version: Specific version to install (e.g., '1.2.3'). If None, always updates to latest.
            
        Returns:
            str: The package specifier to use with npx
        """
        # Determine the package specifier
        package_spec = f"@coana-tech/cli@{version}" if version else "@coana-tech/cli"
        
        # If a specific version is requested, check if it's already installed
        if version:
            try:
                check_cmd = ["npm", "list", "-g", "@coana-tech/cli", "--depth=0"]
                result = subprocess.run(
                    check_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # If npm list succeeds and mentions the specific version, it's installed
                if result.returncode == 0 and f"@coana-tech/cli@{version}" in result.stdout:
                    log.debug(f"@coana-tech/cli@{version} is already installed globally")
                    return package_spec
                    
            except Exception as e:
                log.debug(f"Could not check for existing @coana-tech/cli installation: {e}")
        
        # Install or update the package
        # When no version is specified, always try to update to latest
        if version:
            log.info(f"Installing reachability analysis plugin (@coana-tech/cli@{version})...")
        else:
            log.info("Updating reachability analysis plugin (@coana-tech/cli) to latest version...")
        log.info("This may take a moment...")
        
        try:
            install_cmd = ["npm", "install", "-g", package_spec]
            log.debug(f"Installing with command: {' '.join(install_cmd)}")
            
            result = subprocess.run(
                install_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for installation
            )
            
            if result.returncode != 0:
                log.warning(f"Global installation failed, npx will download on demand")
                log.debug(f"Install stderr: {result.stderr}")
            else:
                log.info("Reachability analysis plugin installed successfully")
                
        except subprocess.TimeoutExpired:
            log.warning("Installation timed out, npx will download on demand")
        except Exception as e:
            log.warning(f"Could not install globally: {e}, npx will download on demand")
        
        return package_spec
    
    
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
        disable_analysis_splitting: bool = False,
        repo_name: Optional[str] = None,
        branch_name: Optional[str] = None,
        version: Optional[str] = None,
        concurrency: Optional[int] = None,
        additional_params: Optional[List[str]] = None,
        allow_unverified: bool = False,
        enable_debug: bool = False,
        use_only_pregenerated_sboms: bool = False,
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
            disable_analysis_splitting: Disable analysis splitting
            repo_name: Repository name
            branch_name: Branch name
            version: Specific version of @coana-tech/cli to use
            concurrency: Concurrency level for analysis (must be >= 1)
            additional_params: Additional parameters to pass to coana CLI
            allow_unverified: Disable SSL certificate verification (sets NODE_TLS_REJECT_UNAUTHORIZED=0)
            enable_debug: Enable debug mode (passes -d flag to coana CLI)
            use_only_pregenerated_sboms: Use only pre-generated CDX and SPDX files for the scan

        Returns:
            Dict containing scan_id and report_path
        """
        # Ensure @coana-tech/cli is installed
        cli_package = self._ensure_coana_cli_installed(version)
        
        # Build CLI command arguments
        cmd = ["npx", cli_package, "run", "."]
        
        # Add required arguments
        output_dir = str(pathlib.Path(output_path).parent)
        log.warning(f"output_dir: {output_dir}")
        log.warning(f"output_path: {output_path}")
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
        
        if disable_analysis_splitting:
            cmd.append("--disable-analysis-splitting")
        
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

        if use_only_pregenerated_sboms:
            cmd.append("--use-only-pregenerated-sboms")

        # Add any additional parameters provided by the user
        if additional_params:
            cmd.extend(additional_params)
        
        # Set up environment variables
        env = os.environ.copy()
        
        # Required environment variables for Coana CLI
        env["SOCKET_ORG_SLUG"] = org_slug
        env["SOCKET_CLI_API_TOKEN"] = self.api_token
        
        # Optional environment variables
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
