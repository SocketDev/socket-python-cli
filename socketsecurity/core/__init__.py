import logging
import os
import sys
import tarfile
import tempfile
import time
import json
from dataclasses import asdict
from pathlib import Path, PurePath
from typing import Dict, List, Tuple, Set, TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from socketsecurity.config import CliConfig
from socketdev import socketdev
from socketdev.exceptions import APIFailure
from socketdev.fullscans import FullScanParams, SocketArtifact
from socketdev.org import Organization
from socketdev.repos import RepositoryInfo
import copy
from socketsecurity import __version__, USER_AGENT
from socketsecurity.core.classes import (
    Alert,
    Diff,
    FullScan,
    Issue,
    Package,
    Purl
)
from socketsecurity.core.exceptions import APIResourceNotFound
from .socket_config import SocketConfig
from .utils import socket_globs
from .resource_utils import check_file_count_against_ulimit
import importlib
logging_std = importlib.import_module("logging")


__all__ = [
    "Core",
    "log",
    "__version__",
    "USER_AGENT",
]

version = __version__
log = logging.getLogger("socketdev")

class Core:
    """Main class for interacting with Socket Security API and processing scan results."""

    ALERT_TYPE_TO_CAPABILITY = {
        "envVars": "Environment Variables",
        "networkAccess": "Network Access",
        "filesystemAccess": "File System Access",
        "shellAccess": "Shell Access",
        "usesEval": "Uses Eval",
        "unsafe": "Unsafe"
    }

    config: SocketConfig
    sdk: socketdev
    cli_config: Optional['CliConfig']

    def __init__(self, config: SocketConfig, sdk: socketdev, cli_config: Optional['CliConfig'] = None) -> None:
        """Initialize Core with configuration and SDK instance."""
        self.config = config
        self.sdk = sdk
        self.cli_config = cli_config
        self.set_org_vars()

    def set_org_vars(self) -> None:
        """Sets the main shared configuration variables for organization access."""
        org_id, org_slug = self.get_org_id_slug()

        self.config.org_id = org_id
        self.config.org_slug = org_slug

        base_path = f"orgs/{org_slug}"
        self.config.full_scan_path = f"{base_path}/full-scans"
        self.config.repository_path = f"{base_path}/repos"

    def get_org_id_slug(self) -> Tuple[str, str]:
        """Gets the Org ID and Org Slug for the API Token."""
        response = self.sdk.org.get(use_types=True)
        organizations: Dict[str, Organization] = response.get("organizations", {})

        if len(organizations) == 1:
            org_id = next(iter(organizations))
            return org_id, organizations[org_id]['slug']
        return None, None

    def get_sbom_data(self, full_scan_id: str) -> List[SocketArtifact]:
        """Returns the list of SBOM artifacts for a full scan."""
        response = self.sdk.fullscans.stream(self.config.org_slug, full_scan_id, use_types=True)
        artifacts: List[SocketArtifact] = []
        if not response.success:
            log.debug(f"Failed to get SBOM data for full-scan {full_scan_id}")
            log.debug(response.message)
            return {}
        if not hasattr(response, "artifacts") or not response.artifacts:
            return artifacts
        for artifact_id in response.artifacts:
            artifacts.append(response.artifacts[artifact_id])
        return artifacts

    def get_sbom_data_list(self, artifacts_dict: Dict[str, SocketArtifact]) -> list[SocketArtifact]:
        """Converts artifacts dictionary to a list."""
        return list(artifacts_dict.values())



    def create_sbom_output(self, diff: Diff) -> dict:
        """Creates CycloneDX output for a given diff."""
        try:
            result = self.sdk.export.cdx_bom(self.config.org_slug, diff.id, use_types=True)
            if not result.success:
                log.error(f"Failed to get CycloneDX Output for full-scan {diff.id}")
                log.error(result.message)
                return {}

            result.pop("success", None)
            return result
        except Exception:
            log.error(f"Unable to get CycloneDX Output for {diff.id}")
            log.error(result.get("message", "No error message provided"))
            return {}

    @staticmethod
    def expand_brace_pattern(pattern: str) -> List[str]:
        """
        Recursively expands brace expressions (e.g., {a,b,c}) into separate patterns, supporting nested braces.
        """
        def recursive_expand(pat: str) -> List[str]:
            stack = []
            for i, c in enumerate(pat):
                if c == '{':
                    stack.append(i)
                elif c == '}' and stack:
                    start = stack.pop()
                    if not stack:
                        # Found the outermost pair
                        before = pat[:start]
                        after = pat[i+1:]
                        inner = pat[start+1:i]
                        # Split on commas not inside nested braces
                        options = []
                        depth = 0
                        last = 0
                        for j, ch in enumerate(inner):
                            if ch == '{':
                                depth += 1
                            elif ch == '}':
                                depth -= 1
                            elif ch == ',' and depth == 0:
                                options.append(inner[last:j])
                                last = j+1
                        options.append(inner[last:])
                        results = []
                        for opt in options:
                            expanded = before + opt + after
                            results.extend(recursive_expand(expanded))
                        return results
            return [pat]
        return recursive_expand(pattern)

    @staticmethod
    def is_excluded(file_path: str, excluded_dirs: Set[str]) -> bool:
        parts = os.path.normpath(file_path).split(os.sep)
        for part in parts:
            if part in excluded_dirs:
                return True
        return False

    def save_submitted_files_list(self, files: List[str], output_path: str) -> None:
        """
        Save the list of submitted file names to a JSON file for debugging.

        Args:
            files: List of file paths that were submitted for scanning
            output_path: Path where to save the JSON file
        """
        try:
            # Calculate total size of all files
            total_size_bytes = 0
            valid_files = []
            
            for file_path in files:
                try:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        file_size = os.path.getsize(file_path)
                        total_size_bytes += file_size
                        valid_files.append(file_path)
                    else:
                        log.warning(f"File not found or not accessible: {file_path}")
                        valid_files.append(file_path)  # Still include in list for debugging
                except OSError as e:
                    log.warning(f"Error accessing file {file_path}: {e}")
                    valid_files.append(file_path)  # Still include in list for debugging
            
            # Convert bytes to human-readable format
            def format_bytes(bytes_value):
                """Convert bytes to human readable format"""
                for unit in ['B', 'KB', 'MB', 'GB']:
                    if bytes_value < 1024.0:
                        return f"{bytes_value:.2f} {unit}"
                    bytes_value /= 1024.0
                return f"{bytes_value:.2f} TB"
            
            file_data = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "total_files": len(valid_files),
                "total_size_bytes": total_size_bytes,
                "total_size_human": format_bytes(total_size_bytes),
                "files": sorted(valid_files)
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(file_data, f, indent=2, ensure_ascii=False)
            
            log.info(f"Saved list of {len(valid_files)} submitted files ({file_data['total_size_human']}) to: {output_path}")
            
        except Exception as e:
            log.error(f"Failed to save submitted files list to {output_path}: {e}")

    def save_manifest_tar(self, files: List[str], output_path: str, base_dir: str) -> None:
        """
        Save all manifest files to a compressed tar.gz archive with original directory structure.

        Args:
            files: List of file paths to include in the archive
            output_path: Path where to save the tar.gz file
            base_dir: Base directory to preserve relative structure
        """
        try:
            # Normalize base directory
            base_dir = os.path.abspath(base_dir)
            if not base_dir.endswith(os.sep):
                base_dir += os.sep

            log.info(f"Creating manifest tar.gz file: {output_path}")
            log.debug(f"Base directory: {base_dir}")

            with tarfile.open(output_path, 'w:gz') as tar:
                for file_path in files:
                    if not os.path.exists(file_path):
                        log.warning(f"File not found, skipping: {file_path}")
                        continue

                    # Calculate relative path within the base directory
                    abs_file_path = os.path.abspath(file_path)
                    if abs_file_path.startswith(base_dir):
                        # File is within base directory - use relative path
                        arcname = os.path.relpath(abs_file_path, base_dir)
                    else:
                        # File is outside base directory - use just the filename
                        arcname = os.path.basename(abs_file_path)
                        log.warning(f"File outside base dir, using basename: {file_path} -> {arcname}")

                    # Normalize archive name to use forward slashes
                    arcname = arcname.replace(os.sep, '/')

                    log.debug(f"Adding to tar: {file_path} -> {arcname}")
                    tar.add(file_path, arcname=arcname)

            # Get tar file size for logging
            tar_size = os.path.getsize(output_path)
            
            def format_bytes(bytes_value):
                """Convert bytes to human readable format"""
                for unit in ['B', 'KB', 'MB', 'GB']:
                    if bytes_value < 1024.0:
                        return f"{bytes_value:.2f} {unit}"
                    bytes_value /= 1024.0
                return f"{bytes_value:.2f} TB"

            tar_size_human = format_bytes(tar_size)
            log.info(f"Successfully created tar.gz with {len(files)} files ({tar_size_human}, {tar_size:,} bytes): {output_path}")

        except Exception as e:
            log.error(f"Failed to save manifest tar.gz to {output_path}: {e}")

    def find_files(self, path: str, ecosystems: Optional[List[str]] = None) -> List[str]:
        """
        Finds supported manifest files in the given path.

        Args:
            path: Path to search for manifest files.
            ecosystems: Optional list of ecosystems to include. If None, all ecosystems are included.

        Returns:
            List of found manifest file paths.
        """
        log.debug("Starting Find Files")
        start_time = time.time()
        files: Set[str] = set()

        # Get supported patterns from the API
        patterns = self.get_supported_patterns()

        for ecosystem in patterns:
            # If ecosystems filter is provided, only include specified ecosystems
            if ecosystems is not None and ecosystem not in ecosystems:
                continue
            if ecosystem in self.config.excluded_ecosystems:
                continue
            log.debug(f'Scanning ecosystem: {ecosystem}')
            ecosystem_patterns = patterns[ecosystem]
            for file_name in ecosystem_patterns:
                original_pattern = ecosystem_patterns[file_name]["pattern"]

                # Expand brace patterns
                expanded_patterns = Core.expand_brace_pattern(original_pattern)

                for pattern in expanded_patterns:
                    case_insensitive_pattern = Core.to_case_insensitive_regex(pattern)
                    
                    log.debug(f"Searching for pattern: {case_insensitive_pattern}")
                    glob_start = time.time()
                    
                    # Use pathlib.Path.rglob() instead of glob.glob() to properly match dotfiles/dotdirs
                    base_path = Path(path)
                    glob_files = base_path.rglob(case_insensitive_pattern)

                    for glob_file in glob_files:
                        glob_file_str = str(glob_file)
                        if os.path.isfile(glob_file_str) and not Core.is_excluded(glob_file_str, self.config.excluded_dirs):
                            files.add(glob_file_str.replace("\\", "/"))

                    glob_end = time.time()
                    log.debug(f"Globbing took {glob_end - glob_start:.4f} seconds")

        file_list = sorted(files)
        file_count = len(file_list)
        log.info(f"Total files found: {file_count}")

        # Check if the number of manifest files might exceed ulimit -n
        ulimit_check = check_file_count_against_ulimit(file_count)
        if ulimit_check["can_check"]:
            if ulimit_check["would_exceed"]:
                log.debug(f"Found {file_count} manifest files, which may exceed the file descriptor limit (ulimit -n = {ulimit_check['soft_limit']})")
                log.debug(f"Available file descriptors: {ulimit_check['available_fds']} (after {ulimit_check['buffer_size']} buffer)")
                log.debug(f"Recommendation: {ulimit_check['recommendation']}")
                log.debug("This may cause 'Too many open files' errors during processing")
            else:
                log.debug(f"File count ({file_count}) is within file descriptor limit ({ulimit_check['soft_limit']})")
        else:
            log.debug(f"Could not check file descriptor limit: {ulimit_check.get('error', 'Unknown error')}")

        return file_list

    def find_sbom_files(self, path: str) -> List[str]:
        """
        Finds only pre-generated SBOM files (CDX and SPDX) in the given path.

        This is used with --reach-use-only-pregenerated-sboms to find only
        pre-computed CycloneDX and SPDX manifest files.

        Args:
            path: Path to search for SBOM files.

        Returns:
            List of found CDX and SPDX file paths.
        """
        log.debug("Starting Find SBOM Files (CDX and SPDX only)")
        sbom_ecosystems = ['cdx', 'spdx']
        return self.find_files(path, ecosystems=sbom_ecosystems)

    def get_supported_patterns(self) -> Dict:
        """
        Gets supported file patterns from the Socket API.

        Returns:
            Dictionary of supported file patterns with 'general' key removed
        """
        response = self.sdk.report.supported()
        if not response:
            log.error("Failed to get supported patterns from API")
            # Import the old patterns as fallback
            from .utils import socket_globs
            return socket_globs

        # Remove the 'general' key if it exists
        if 'general' in response:
            response.pop('general')

        # The response is already in the format we need
        return response

    def has_manifest_files(self, files: list) -> bool:
        """
        Checks if any files in the list are supported manifest files.

        Args:
            files: List of file paths to check

        Returns:
            True if any files match manifest patterns, False otherwise
        """
        # Get supported patterns
        try:
            patterns = self.get_supported_patterns()
        except Exception as e:
            log.error(f"Error getting supported patterns from API: {e}")
            log.warning("Falling back to local patterns")
            from .utils import socket_globs as fallback_patterns
            patterns = fallback_patterns

        # Normalize all file paths for matching
        norm_files = [f.replace('\\', '/').lstrip('./') for f in files]

        for ecosystem in patterns:
            ecosystem_patterns = patterns[ecosystem]
            for file_name in ecosystem_patterns:
                pattern_str = ecosystem_patterns[file_name]["pattern"]
                # Expand brace patterns for each manifest pattern
                expanded_patterns = Core.expand_brace_pattern(pattern_str)
                for exp_pat in expanded_patterns:
                    # If pattern doesn't contain '/', prepend '**/' to match files in any subdirectory
                    # This ensures patterns like '*requirements.txt' match '.test/requirements.txt'
                    if '/' not in exp_pat:
                        exp_pat = f"**/{exp_pat}"
                    
                    for file in norm_files:
                        # Use PurePath.match for glob-like matching
                        if PurePath(file).match(exp_pat):
                            return True
        return False

    def check_file_count_limit(self, file_count: int) -> dict:
        """
        Check if the given file count would exceed the system's file descriptor limit.
        
        Args:
            file_count: Number of files to check
            
        Returns:
            Dictionary with check results including recommendations
        """
        return check_file_count_against_ulimit(file_count)

    @staticmethod
    def to_case_insensitive_regex(input_string: str) -> str:
        """
        Converts a string into a case-insensitive regex pattern.

        Args:
            input_string: String to convert

        Returns:
            Case-insensitive regex pattern

        Example:
            "pipfile" -> "[Pp][Ii][Pp][Ff][Ii][Ll][Ee]"
        """
        return ''.join(f'[{char.lower()}{char.upper()}]' if char.isalpha() else char for char in input_string)

    @staticmethod
    def empty_head_scan_file() -> List[str]:
        """
        Creates a temporary empty file for baseline scans when no head scan exists.
        
        Returns:
            List containing path to a temporary empty file
        """
        # Create a temporary directory and then create our specific filename
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, '.socket.facts.json')
        
        # Create the empty file
        with open(temp_path, 'w') as f:
            pass  # Creates an empty file
        
        log.debug(f"Created temporary empty file for baseline scan: {temp_path}")
        return [temp_path]

    def finalize_tier1_scan(self, full_scan_id: str, facts_file_path: str) -> bool:
        """
        Finalize a tier 1 reachability scan by associating it with a full scan.

        This function reads the tier1ReachabilityScanId from the facts file and
        calls the SDK to link it with the specified full scan.

        Linking the tier 1 scan to the full scan helps the Socket team debug potential issues.

        Args:
            full_scan_id: The ID of the full scan to associate with the tier 1 scan
            facts_file_path: Path to the .socket.facts.json file containing the tier1ReachabilityScanId

        Returns:
            True if successful, False otherwise
        """
        log.debug(f"Finalizing tier 1 scan for full scan {full_scan_id}")

        # Read the tier1ReachabilityScanId from the facts file
        try:
            if not os.path.exists(facts_file_path):
                log.debug(f"Facts file not found: {facts_file_path}")
                return False

            with open(facts_file_path, 'r') as f:
                facts = json.load(f)

            tier1_scan_id = facts.get('tier1ReachabilityScanId')
            if not tier1_scan_id:
                log.debug(f"No tier1ReachabilityScanId found in {facts_file_path}")
                return False

            tier1_scan_id = tier1_scan_id.strip()
            log.debug(f"Found tier1ReachabilityScanId: {tier1_scan_id}")

        except (json.JSONDecodeError, IOError) as e:
            log.debug(f"Failed to read tier1ReachabilityScanId from {facts_file_path}: {e}")
            return False

        # Call the SDK to finalize the tier 1 scan
        try:
            success = self.sdk.fullscans.finalize_tier1(
                full_scan_id=full_scan_id,
                tier1_reachability_scan_id=tier1_scan_id,
            )

            if success:
                log.debug(f"Successfully finalized tier 1 scan {tier1_scan_id} for full scan {full_scan_id}")
            return success

        except Exception as e:
            log.debug(f"Unable to finalize tier 1 scan: {e}")
            return False

    def create_full_scan(self, files: List[str], params: FullScanParams, base_paths: Optional[List[str]] = None) -> FullScan:
        """
        Creates a new full scan via the Socket API.

        Args:
            files: List of file paths to scan
            params: Parameters for the full scan
            base_paths: List of base paths for the scan (optional)

        Returns:
            FullScan object with scan results
        """
        log.info("Creating new full scan")
        create_full_start = time.time()

        res = self.sdk.fullscans.post(files, params, use_types=True, use_lazy_loading=True, max_open_files=50, base_paths=base_paths)
        if not res.success:
            log.error(f"Error creating full scan: {res.message}, status: {res.status}")
            raise Exception(f"Error creating full scan: {res.message}, status: {res.status}")

        full_scan = FullScan(**asdict(res.data))
        create_full_end = time.time()
        total_time = create_full_end - create_full_start
        log.debug(f"New Full Scan created in {total_time:.2f} seconds")

        # Finalize tier1 scan if reachability analysis was enabled
        if self.cli_config and self.cli_config.reach:
            facts_file_path = os.path.join(
                self.cli_config.target_path or ".", 
                self.cli_config.reach_output_file
            )
            log.debug(f"Reachability analysis enabled, finalizing tier1 scan for full scan {full_scan.id}")
            try:
                success = self.finalize_tier1_scan(full_scan.id, facts_file_path)
                if success:
                    log.debug(f"Successfully finalized tier1 scan for full scan {full_scan.id}")
                else:
                    log.debug(f"Failed to finalize tier1 scan for full scan {full_scan.id}")
            except Exception as e:
                log.warning(f"Error finalizing tier1 scan for full scan {full_scan.id}: {e}")

        return full_scan

    def create_full_scan_with_report_url(
            self,
            paths: List[str],
            params: FullScanParams,
            no_change: bool = False,
            save_files_list_path: Optional[str] = None,
            save_manifest_tar_path: Optional[str] = None,
            base_paths: Optional[List[str]] = None,
            explicit_files: Optional[List[str]] = None
    ) -> Diff:
        """Create a new full scan and return with html_report_url.

        Args:
            paths: List of paths to look for manifest files
            params: Query params for the Full Scan endpoint
            no_change: If True, return empty result
            save_files_list_path: Optional path to save submitted files list for debugging
            save_manifest_tar_path: Optional path to save manifest files tar.gz archive
            base_paths: List of base paths for the scan (optional)
            explicit_files: Optional list of explicit files to use instead of discovering files

        Returns:
            Dict with full scan data including html_report_url
        """
        log.debug(f"starting create_full_scan_with_report_url with no_change: {no_change}")
        diff = Diff(
            id="NO_SCAN_RAN",
            report_url="",
            diff_url=""
        )
        if no_change:
            return diff

        # Use explicit files if provided, otherwise find manifest files from all paths
        if explicit_files is not None:
            all_files = explicit_files
            log.debug(f"Using {len(all_files)} explicit files instead of discovering files")
        else:
            all_files = []
            for path in paths:
                files = self.find_files(path)
                all_files.extend(files)
        
        # Save submitted files list if requested
        if save_files_list_path and all_files:
            self.save_submitted_files_list(all_files, save_files_list_path)
        
        # Save manifest tar.gz if requested (use first path as base)
        if save_manifest_tar_path and all_files and paths:
            self.save_manifest_tar(all_files, save_manifest_tar_path, paths[0])
        
        # If no supported files found, create empty scan
        if not all_files:
            log.info("No supported manifest files found - creating empty scan")
            empty_files = Core.empty_head_scan_file()
            try:
                # Create new scan
                new_scan_start = time.time()
                new_full_scan = self.create_full_scan(empty_files, params, base_paths=base_paths)
                new_scan_end = time.time()
                log.info(f"Total time to create empty full scan: {new_scan_end - new_scan_start:.2f}")
                
                # Clean up the temporary empty file
                for temp_file in empty_files:
                    try:
                        os.unlink(temp_file)
                        log.debug(f"Cleaned up temporary file: {temp_file}")
                    except OSError as e:
                        log.warning(f"Failed to clean up temporary file {temp_file}: {e}")
            except Exception as e:
                # Clean up temp files even if scan creation fails
                for temp_file in empty_files:
                    try:
                        os.unlink(temp_file)
                    except OSError:
                        pass
                raise e
        else:
            try:
                # Create new scan
                new_scan_start = time.time()
                new_full_scan = self.create_full_scan(all_files, params, base_paths=base_paths)
                new_scan_end = time.time()
                log.info(f"Total time to create new full scan: {new_scan_end - new_scan_start:.2f}")
            except APIFailure as e:
                log.error(f"Failed to create full scan: {e}")
                raise

        # Construct report URL
        base_socket = "https://socket.dev/dashboard/org"
        diff.report_url = f"{base_socket}/{self.config.org_slug}/sbom/{new_full_scan.id}"
        diff.diff_url = diff.report_url
        diff.id = new_full_scan.id
        diff.packages = {}

        # Return result in the format expected by the user
        return diff

    def get_full_scan(self, full_scan_id: str) -> FullScan:
        """
        Get a FullScan object for an existing full scan including sbom_artifacts and packages.

        Args:
            full_scan_id: The ID of the full scan to get

        Returns:
            The FullScan object with populated artifacts and packages
        """
        full_scan_metadata = self.sdk.fullscans.metadata(self.config.org_slug, full_scan_id, use_types=True)
        full_scan = FullScan(**asdict(full_scan_metadata.data))
        full_scan_artifacts_dict = self.get_sbom_data(full_scan_id)
        full_scan.sbom_artifacts = self.get_sbom_data_list(full_scan_artifacts_dict)
        full_scan.packages = self.create_packages_dict(full_scan.sbom_artifacts)
        return full_scan

    def create_packages_dict(self, sbom_artifacts: list[SocketArtifact]) -> dict[str, Package]:
        """
        Creates a dictionary of Package objects from SBOM artifacts.

        Args:
            sbom_artifacts: List of SBOM artifacts from the scan

        Returns:
            Dictionary mapping package IDs to Package objects
        """
        packages = {}
        top_level_count = {}
        for artifact in sbom_artifacts:
            package = Package.from_socket_artifact(asdict(artifact))
            if package.id in packages:
                print("Duplicate package?")
            else:
                package.license_text = self.get_package_license_text(package)
                packages[package.id] = package
                if package.topLevelAncestors:
                    for top_id in package.topLevelAncestors:
                        if top_id not in top_level_count:
                            top_level_count[top_id] = 1
                        else:
                            top_level_count[top_id] += 1

        for package_id, package in packages.items():
            package.transitives = top_level_count.get(package_id, 0)

        return packages

    def get_package_license_text(self, package: Package) -> str:
        """
        Gets the license text for a package if available.

        Args:
            package: Package object to get license text for

        Returns:
            License text if found, empty string otherwise
        """
        if package.license is None:
            return ""

        license_raw = package.license
        data = self.sdk.licensemetadata.post([license_raw], {'includetext': 'true'})
        license_str = data[0].get('text') if data and len(data) == 1 else ""
        return license_str

    def get_repo_info(self, repo_slug: str, default_branch: str = "socket-default-branch") -> RepositoryInfo:
        """
        Gets repository information from the Socket API.

        Args:
            repo_slug: Repository slug to get info for
            default_branch: Default branch string to use if the repo doesn't exist

        Returns:
            RepositoryInfo object

        Raises:
            Exception: If API request fails
        """
        try:
            # Need to switch to either standard logger or not call our module logging so that there isn't a conflict
            # Also need to update the SDK to not emit log in a way that can't be trapped by try/except
            sdk_logger = logging_std.getLogger("socketdev")
            original_level = sdk_logger.level
            sdk_logger.setLevel(logging_std.CRITICAL)
            response = self.sdk.repos.repo(self.config.org_slug, repo_slug, use_types=True)
            sdk_logger.setLevel(original_level)
            if not response.success:
                log.error(f"Failed to get repository: {response.status}")
                # log.error(response.message)
        except APIFailure:
            log.warning(f"Failed to get repository {repo_slug}, attempting to create it")
            try:

                create_response = self.sdk.repos.post(
                    self.config.org_slug,
                    name=repo_slug,
                    default_branch=default_branch,
                    visibility=self.config.repo_visibility
                )

                # Check if the response is empty (failure) or has content (success)
                if not create_response:
                    log.error("Failed to create repository: empty response")
                    raise Exception("Failed to create repository: empty response")
                else:
                    response = self.sdk.repos.repo(self.config.org_slug, repo_slug, use_types=True)
                    return response.data

            except APIFailure as e:
                log.error(f"API failure while creating repository: {e}")
                sys.exit(2) # Exit here with code 2. Code 1 indicates a successfully-detected security issue.

        return response.data

    def get_head_scan_for_repo(self, repo_slug: str) -> str:
        """
        Gets the head scan ID for a repository.

        Args:
            repo_slug: Repository slug to get head scan for

        Returns:
            Head scan ID if it exists, None otherwise
        """
        repo_info = self.get_repo_info(repo_slug)
        return repo_info.head_full_scan_id if repo_info.head_full_scan_id else None

    @staticmethod
    def update_package_values(pkg: Package) -> Package:
        pkg.purl = f"{pkg.name}@{pkg.version}"
        pkg.url = f"https://socket.dev/{pkg.type}/package"
        if pkg.namespace:
            pkg.purl = f"{pkg.namespace}/{pkg.purl}"
            pkg.url += f"/{pkg.namespace}"
        pkg.url += f"/{pkg.name}/overview/{pkg.version}"
        return pkg

    def get_license_text_via_purl(self, packages: dict[str, Package], batch_size: int = 5000) -> dict:
        """Get license attribution and details via PURL endpoint in batches.
        
        Args:
            packages: Dictionary of packages to get license info for
            batch_size: Maximum number of packages to process per API call (1-9999)
            
        Returns:
            Updated packages dictionary with licenseAttrib and licenseDetails populated
        """
        # Validate batch size
        batch_size = max(1, min(9999, batch_size))
        
        # Build list of all components
        all_components = []
        for purl in packages:
            full_purl = f"pkg:/{purl}"
            all_components.append({"purl": full_purl})
        
        # Process in batches
        total_components = len(all_components)
        log.debug(f"Processing {total_components} packages in batches of {batch_size}")
        
        for i in range(0, total_components, batch_size):
            batch_components = all_components[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (total_components + batch_size - 1) // batch_size
            log.debug(f"Processing batch {batch_num}/{total_batches} ({len(batch_components)} packages)")
            
            results = self.sdk.purl.post(
                license=True,
                components=batch_components,
                licenseattrib=True,
                licensedetails=True
            )
            
            purl_packages = []
            for result in results:
                ecosystem = result["type"]
                name = result["name"]
                package_version = result["version"]
                licenseDetails = result.get("licenseDetails")
                licenseAttrib = result.get("licenseAttrib")
                purl = f"{ecosystem}/{name}@{package_version}"
                if purl not in purl_packages and purl in packages:
                    packages[purl].licenseAttrib = licenseAttrib
                    packages[purl].licenseDetails = licenseDetails
        
        return packages

    def get_added_and_removed_packages(
            self,
            head_full_scan_id: str,
            new_full_scan_id: str
    ) -> Tuple[Dict[str, Package], Dict[str, Package], Dict[str, Package]]:
        """
        Get packages that were added and removed between scans.

        Args:
            head_full_scan_id: Previous scan (maybe None if first scan)
            new_full_scan_id: New scan just created

        Returns:
            Tuple of (added_packages, removed_packages) dictionaries
        """

        log.info(f"Comparing scans - Head scan ID: {head_full_scan_id}, New scan ID: {new_full_scan_id}")
        diff_start = time.time()
        try:
            diff_report = (
                self.sdk.fullscans.stream_diff
                           (
                    self.config.org_slug,
                    head_full_scan_id,
                    new_full_scan_id,
                    use_types=True
                ).data
            )
        except APIFailure as e:
            log.error(f"API Error: {e}")
            sys.exit(1)
        except Exception as e:
            import traceback
            log.error(f"Error getting diff report: {str(e)}")
            log.error(f"Stack trace:\n{traceback.format_exc()}")
            raise

        diff_end = time.time()
        log.info(f"Diff Report Gathered in {diff_end - diff_start:.2f} seconds")
        log.info("Diff report artifact counts:")
        log.info(f"Added: {len(diff_report.artifacts.added)}")
        log.info(f"Removed: {len(diff_report.artifacts.removed)}")
        log.info(f"Unchanged: {len(diff_report.artifacts.unchanged)}")
        log.info(f"Replaced: {len(diff_report.artifacts.replaced)}")
        log.info(f"Updated: {len(diff_report.artifacts.updated)}")

        added_artifacts = diff_report.artifacts.added + diff_report.artifacts.updated
        removed_artifacts = diff_report.artifacts.removed + diff_report.artifacts.replaced
        unchanged_artifacts = diff_report.artifacts.unchanged

        added_packages: Dict[str, Package] = {}
        removed_packages: Dict[str, Package] = {}
        packages: Dict[str, Package] = {}
        for artifact in added_artifacts:
            try:
                pkg = Package.from_diff_artifact(asdict(artifact))
                pkg = Core.update_package_values(pkg)
                added_packages[artifact.id] = pkg
                full_purl = f"{pkg.type}/{pkg.purl}"
                if full_purl not in packages:
                    packages[full_purl] = pkg
            except KeyError:
                log.error(f"KeyError: Could not create package from added artifact {artifact.id}")
                log.error(f"Artifact details - name: {artifact.name}, version: {artifact.version}")
                log.error("No matching packages found in new_full_scan")

        for artifact in unchanged_artifacts:
            try:
                pkg = Package.from_diff_artifact(asdict(artifact))
                pkg = Core.update_package_values(pkg)
                full_purl = f"{pkg.type}/{pkg.purl}"
                if full_purl not in packages:
                    packages[full_purl] = pkg
            except KeyError:
                log.error(f"KeyError: Could not create package from unchanged artifact {artifact.id}")
                log.error(f"Artifact details - name: {artifact.name}, version: {artifact.version}")
                log.error("No matching packages found in new_full_scan")

        for artifact in removed_artifacts:
            try:
                pkg = Package.from_diff_artifact(asdict(artifact))
                pkg = Core.update_package_values(pkg)
                if pkg.namespace:
                    pkg.purl += f"{pkg.namespace}/{pkg.purl}"
                removed_packages[artifact.id] = pkg
            except KeyError:
                log.error(f"KeyError: Could not create package from removed artifact {artifact.id}")
                log.error(f"Artifact details - name: {artifact.name}, version: {artifact.version}")
                log.error("No matching packages found in head_full_scan")

        # Only fetch license details if generate_license is enabled
        if self.cli_config and self.cli_config.generate_license:
            log.debug("Fetching license details via PURL endpoint")
            batch_size = self.cli_config.max_purl_batch_size if self.cli_config else 5000
            packages = self.get_license_text_via_purl(packages, batch_size=batch_size)
        else:
            log.debug("Skipping PURL endpoint call (--generate-license not set)")
        
        return added_packages, removed_packages, packages

    def create_new_diff(
            self,
            paths: List[str],
            params: FullScanParams,
            no_change: bool = False,
            save_files_list_path: Optional[str] = None,
            save_manifest_tar_path: Optional[str] = None,
            base_paths: Optional[List[str]] = None,
            explicit_files: Optional[List[str]] = None
    ) -> Diff:
        """Create a new diff using the Socket SDK.

        Args:
            paths: List of paths to look for manifest files
            params: Query params for the Full Scan endpoint
            no_change: If True, return empty diff
            save_files_list_path: Optional path to save submitted files list for debugging
            save_manifest_tar_path: Optional path to save manifest files tar.gz archive
            base_paths: List of base paths for the scan (optional)
            explicit_files: Optional list of explicit files to use instead of discovering files
        """
        log.debug(f"starting create_new_diff with no_change: {no_change}")
        if no_change:
            return Diff(id="NO_DIFF_RAN", diff_url="", report_url="")

        # Use explicit files if provided, otherwise find manifest files from all paths
        if explicit_files is not None:
            all_files = explicit_files
            log.debug(f"Using {len(all_files)} explicit files instead of discovering files")
        else:
            all_files = []
            for path in paths:
                files = self.find_files(path)
                all_files.extend(files)
        
        # Save submitted files list if requested
        if save_files_list_path and all_files:
            self.save_submitted_files_list(all_files, save_files_list_path)
        
        # Save manifest tar.gz if requested (use first path as base)
        if save_manifest_tar_path and all_files and paths:
            self.save_manifest_tar(all_files, save_manifest_tar_path, paths[0])
        
        # If no supported files found, create empty scan for comparison
        scan_files = all_files
        if not all_files:
            log.info("No supported manifest files found - creating empty scan for diff comparison")
            scan_files = Core.empty_head_scan_file()

        try:
            # Get head scan ID
            head_full_scan_id = self.get_head_scan_for_repo(params.repo)
        except APIResourceNotFound:
            head_full_scan_id = None

        # If no head scan exists, create an empty baseline scan
        if head_full_scan_id is None:
            log.info("No previous scan found - creating empty baseline scan")
            new_params = copy.deepcopy(params.__dict__)
            new_params.pop('include_license_details')
            tmp_params = FullScanParams(**new_params)
            tmp_params.include_license_details = params.include_license_details
            tmp_params.tmp = True
            tmp_params.set_as_pending_head = False
            tmp_params.make_default_branch = False
            
            # Create baseline scan with empty file
            empty_files = Core.empty_head_scan_file()
            try:
                head_full_scan = self.create_full_scan(empty_files, tmp_params, base_paths=base_paths)
                head_full_scan_id = head_full_scan.id
                log.debug(f"Created empty baseline scan: {head_full_scan_id}")
                
                # Clean up the temporary empty file
                for temp_file in empty_files:
                    try:
                        os.unlink(temp_file)
                        log.debug(f"Cleaned up temporary file: {temp_file}")
                    except OSError as e:
                        log.warning(f"Failed to clean up temporary file {temp_file}: {e}")
            except Exception as e:
                # Clean up temp files even if scan creation fails
                for temp_file in empty_files:
                    try:
                        os.unlink(temp_file)
                    except OSError:
                        pass
                raise e

        # Create new scan
        temp_files_to_cleanup = []
        if not all_files:  # We're using empty scan files
            temp_files_to_cleanup = scan_files
            
        try:
            new_scan_start = time.time()
            new_full_scan = self.create_full_scan(scan_files, params, base_paths=base_paths)
            new_scan_end = time.time()
            log.info(f"Total time to create new full scan: {new_scan_end - new_scan_start:.2f}")
        except APIFailure as e:
            log.error(f"API Error: {e}")
            # Clean up temp files if any
            for temp_file in temp_files_to_cleanup:
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass
            sys.exit(1)
        except Exception as e:
            import traceback
            log.error(f"Error creating new full scan: {str(e)}")
            log.error(f"Stack trace:\n{traceback.format_exc()}")
            # Clean up temp files if any
            for temp_file in temp_files_to_cleanup:
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass
            raise
        finally:
            # Clean up temporary empty files if they were created
            for temp_file in temp_files_to_cleanup:
                try:
                    os.unlink(temp_file)
                    log.debug(f"Cleaned up temporary file: {temp_file}")
                except OSError as e:
                    log.warning(f"Failed to clean up temporary file {temp_file}: {e}")

        # Handle diff generation - now we always have both scans
        (
            added_packages,
            removed_packages,
            packages
        ) = self.get_added_and_removed_packages(head_full_scan_id, new_full_scan.id)

        diff = self.create_diff_report(added_packages, removed_packages)
        diff.packages = packages

        base_socket = "https://socket.dev/dashboard/org"
        diff.id = new_full_scan.id

        report_url = f"{base_socket}/{self.config.org_slug}/sbom/{diff.id}"
        if not params.include_license_details:
            report_url += "?include_license_details=false"
        diff.report_url = report_url
        diff.new_scan_id = new_full_scan.id

        if head_full_scan_id is not None:
            diff.diff_url = f"{base_socket}/{self.config.org_slug}/diff/{head_full_scan_id}/{diff.id}"
        else:
            diff.diff_url = diff.report_url

        return diff

    def create_diff_report(
        self,
        added_packages: Dict[str, Package],
        removed_packages: Dict[str, Package],
        direct_only: bool = True
    ) -> Diff:
        """
        Creates a diff report comparing two sets of packages.

        Takes packages that were added and removed between two scans and:
        1. Records new/removed packages (direct only by default)
        2. Collects alerts from both sets of packages
        3. Determines new capabilities introduced

        Args:
            added_packages: Dict of packages added in new scan
            removed_packages: Dict of packages removed in new scan
            direct_only: If True, only direct dependencies are included in new/removed lists
                        (but alerts are still processed for all packages)

        Returns:
            Diff object containing the comparison results
        """
        diff = Diff()

        alerts_in_added_packages: Dict[str, List[Issue]] = {}
        alerts_in_removed_packages: Dict[str, List[Issue]] = {}

        seen_new_packages = set()
        seen_removed_packages = set()

        for package_id, package in added_packages.items():
            purl = self.create_purl(package_id, added_packages)
            base_purl = f"{purl.ecosystem}/{purl.name}@{purl.version}"

            if (not direct_only or package.direct) and base_purl not in seen_new_packages:
                diff.new_packages.append(purl)
                seen_new_packages.add(base_purl)

            self.add_package_alerts_to_collection(
                package=package,
                alerts_collection=alerts_in_added_packages,
                packages=added_packages
            )

        for package_id, package in removed_packages.items():
            purl = self.create_purl(package_id, removed_packages)
            base_purl = f"{purl.ecosystem}/{purl.name}@{purl.version}"

            if (not direct_only or package.direct) and base_purl not in seen_removed_packages:
                diff.removed_packages.append(purl)
                seen_removed_packages.add(base_purl)

            self.add_package_alerts_to_collection(
                package=package,
                alerts_collection=alerts_in_removed_packages,
                packages=removed_packages
            )

        diff.new_alerts = Core.get_new_alerts(
            alerts_in_added_packages,
            alerts_in_removed_packages
        )

        diff.new_capabilities = Core.get_capabilities_for_added_packages(added_packages)

        Core.add_purl_capabilities(diff)
        if not hasattr(diff, "diff_url"):
            diff.diff_url = None
        if not hasattr(diff, "report_url"):
            diff.report_url = None

        return diff

    def create_purl(self, package_id: str, packages: dict[str, Package]) -> Purl:
        """
        Creates the extended PURL data for package identification and tracking.

        Args:
            package_id: Package ID to create PURL data for
            packages: Dictionary of all packages for transitive dependency lookup

        Returns:
            Purl object containing package metadata and dependency information
        """
        package = packages[package_id]
        introduced_by = Core.get_source_data(package, packages)
        purl = Purl(
            id=package.id,
            name=package.name,
            version=package.version,
            ecosystem=package.type,
            direct=package.direct,
            introduced_by=introduced_by,
            author=package.author or [],
            size=package.size,
            transitives=package.transitives,
            url=package.url,
            purl=package.purl,
            scores=package.score
        )
        return purl


    @staticmethod
    def get_source_data(package: Package, packages: dict) -> list:
        """
        Determines how a package was introduced into the dependency tree.

        For direct dependencies, records the manifest file.
        For transitive dependencies, records the top-level package that introduced it.

        Args:
            package: Package to analyze
            packages: Dictionary of all packages for ancestor lookup

        Returns:
            List of tuples containing (source, manifest_file) information
        """
        introduced_by = []
        if package.direct:
            manifests = ""
            if not hasattr(package, "manifestFiles") or package.manifestFiles is None:
                return introduced_by
            for manifest_data in package.manifestFiles:
                manifest_file = manifest_data.get("file")
                manifests += f"{manifest_file};"
            manifests = manifests.rstrip(";")
            source = ("direct", manifests)
            introduced_by.append(source)
        else:
            if not package.topLevelAncestors:
                return introduced_by
            for top_id in package.topLevelAncestors:
                top_package = packages.get(top_id)
                if top_package:
                    manifests = ""
                    top_purl = f"{top_package.type}/{top_package.name}@{top_package.version}"
                    if hasattr(top_package, "manifestFiles") and top_package.manifestFiles:
                        for manifest_data in top_package.manifestFiles:
                            manifest_file = manifest_data.get("file")
                            manifests += f"{manifest_file};"
                        manifests = manifests.rstrip(";")
                        source = (top_purl, manifests)
                        introduced_by.append(source)
                else:
                    pass
                    # log.debug(f"Unable to get top level package info for {top_id}")
        return introduced_by

    @staticmethod
    def add_purl_capabilities(diff: Diff) -> None:
        """
        Adds capability information to each package in the diff's new_packages list.

        Args:
            diff: Diff object to update with capability information
        """
        new_packages = []
        for purl in diff.new_packages:
            if purl.id in diff.new_capabilities:
                new_purl = Purl(
                    **{**purl.__dict__,
                    "capabilities": diff.new_capabilities[purl.id]}
                )
                new_packages.append(new_purl)
            else:
                new_packages.append(purl)

        diff.new_packages = new_packages

    def add_package_alerts_to_collection(self, package: Package, alerts_collection: dict, packages: dict) -> dict:
        """
        Processes alerts from a package and adds them to a shared alerts collection.

        Args:
            package: Package to process alerts from
            alerts_collection: Dictionary to store processed alerts
            packages: Dictionary of all packages for dependency lookup

        Returns:
            Updated alerts collection dictionary
        """
        default_props = type('EmptyProps', (), {
            'description': "",
            'title': "",
            'suggestion': "",
            'nextStepTitle': ""
        })()

        for alert_item in package.alerts:
            alert = Alert(**alert_item)
            props = getattr(self.config.all_issues, alert.type, default_props)
            introduced_by = self.get_source_data(package, packages)
            
            # Handle special case for license policy violations
            title = props.title
            if alert.type == "licenseSpdxDisj" and not title:
                title = "License Policy Violation"
            
            issue_alert = Issue(
                pkg_type=package.type,
                pkg_name=package.name,
                pkg_version=package.version,
                pkg_id=package.id,
                props=alert.props,
                key=alert.key,
                type=alert.type,
                severity=alert.severity,
                description=props.description,
                title=title,
                suggestion=props.suggestion,
                next_step_title=props.nextStepTitle,
                introduced_by=introduced_by,
                purl=package.purl,
                url=package.url
            )

            # Use action from API (from security policy, label policy, triage, etc.)
            if 'action' in alert_item and alert_item['action']:
                action = alert_item['action']
                setattr(issue_alert, action, True)

            if issue_alert.key not in alerts_collection:
                alerts_collection[issue_alert.key] = [issue_alert]
            else:
                alerts_collection[issue_alert.key].append(issue_alert)

        return alerts_collection

    @staticmethod
    def save_file(file_name: str, content: str) -> None:
        """
        Saves content to a file, raising an error if the save fails.

        Args:
            file_name: Path to save the file
            content: Content to write to the file

        Raises:
            IOError: If file cannot be written
        """
        try:
            with open(file_name, "w") as f:
                f.write(content)
        except IOError as e:
            log.error(f"Failed to save file {file_name}: {e}")
            raise

    @staticmethod
    def get_capabilities_for_added_packages(added_packages: Dict[str, Package]) -> Dict[str, List[str]]:
        """
        Maps added packages to their capabilities based on their alerts.

        Args:
            added_packages: Dictionary of packages added in new scan

        Returns:
            Dictionary mapping package IDs to their capability lists
        """
        capabilities: Dict[str, List[str]] = {}

        for package_id, package in added_packages.items():
            for alert in package.alerts:
                if alert["type"] in Core.ALERT_TYPE_TO_CAPABILITY:
                    value = Core.ALERT_TYPE_TO_CAPABILITY[alert["type"]]

                    if package_id not in capabilities:
                        capabilities[package_id] = [value]
                    elif value not in capabilities[package_id]:
                        capabilities[package_id].append(value)

        return capabilities

    @staticmethod
    def get_new_alerts(
        added_package_alerts: Dict[str, List[Issue]],
        removed_package_alerts: Dict[str, List[Issue]],
        ignore_readded: bool = True
    ) -> List[Issue]:
        """
        Find alerts that are new or changed between added and removed packages.

        Args:
            added_package_alerts: Dictionary of alerts from packages that were added
            removed_package_alerts: Dictionary of alerts from packages that were removed
            ignore_readded: If True, don't report alerts that were both removed and added

        Returns:
            List of newly found alerts
        """
        alerts: List[Issue] = []
        consolidated_alerts = set()

        for alert_key in added_package_alerts:
            if alert_key not in removed_package_alerts:
                new_alerts = added_package_alerts[alert_key]
                for alert in new_alerts:
                    # Consolidate by package and alert type, not by manifest details
                    alert_str = f"{alert.purl},{alert.type}"

                    if alert.error or alert.warn:
                        if alert_str not in consolidated_alerts:
                            alerts.append(alert)
                            consolidated_alerts.add(alert_str)
            else:
                new_alerts = added_package_alerts[alert_key]
                removed_alerts = removed_package_alerts[alert_key]

                for alert in new_alerts:
                    # Consolidate by package and alert type, not by manifest details
                    alert_str = f"{alert.purl},{alert.type}"

                    # Only add if:
                    # 1. Alert isn't in removed packages (or we're not ignoring readded alerts)
                    # 2. We haven't already recorded this alert
                    # 3. It's an error or warning
                    if (not ignore_readded or alert not in removed_alerts) and alert_str not in consolidated_alerts:
                        if alert.error or alert.warn:
                            alerts.append(alert)
                            consolidated_alerts.add(alert_str)

        return alerts
