import base64
import json
import logging
import time
from dataclasses import asdict
from glob import glob
from pathlib import PurePath
from typing import BinaryIO, Dict, List, Optional, Tuple
from itertools import chain

from socketdev import socketdev
from socketdev.fullscans import (
    FullScanParams,
    SocketArtifact,
    DiffArtifact,
)
from socketdev.org import Organization
from socketdev.repos import RepositoryInfo
from socketdev.settings import SecurityPolicyRule

from socketsecurity import __version__
from socketsecurity.core.classes import (
    Alert,
    Diff,
    FullScan,
    Issue,
    Package,
    Purl,
)
from socketsecurity.core.exceptions import (
    APIResourceNotFound,
)
from socketsecurity.core.licenses import Licenses

from .socket_config import SocketConfig
from .utils import socket_globs

__all__ = [
    "Core",
    "log",
    "__version__",
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

    def __init__(self, config: SocketConfig, sdk: socketdev) -> None:
        """Initialize Core with configuration and SDK instance."""
        self.config = config
        self.sdk = sdk
        self.set_org_vars()

    def set_org_vars(self) -> None:
        """Sets the main shared configuration variables for organization access."""
        org_id, org_slug = self.get_org_id_slug()

        self.config.org_id = org_id
        self.config.org_slug = org_slug

        base_path = f"orgs/{org_slug}"
        self.config.full_scan_path = f"{base_path}/full-scans"
        self.config.repository_path = f"{base_path}/repos"

        self.config.security_policy = self.get_security_policy()

    def get_org_id_slug(self) -> Tuple[str, str]:
        """Gets the Org ID and Org Slug for the API Token."""
        response = self.sdk.org.get()
        organizations: Dict[str, Organization] = response.get("organizations", {})

        if len(organizations) == 1:
            org_id = next(iter(organizations))
            return org_id, organizations[org_id]['slug']
        return None, None

    def get_sbom_data(self, full_scan_id: str) -> Dict[str, SocketArtifact]:
        """Returns the list of SBOM artifacts for a full scan."""
        response = self.sdk.fullscans.stream(self.config.org_slug, full_scan_id)
        if not response.success:
            log.debug(f"Failed to get SBOM data for full-scan {full_scan_id}")
            log.debug(response.message)
            return {}

        return response.artifacts
    
    def get_sbom_data_list(self, artifacts_dict: Dict[str, SocketArtifact]) -> list[SocketArtifact]:
        """Converts artifacts dictionary to a list."""
        return list(artifacts_dict.values())

    def get_security_policy(self) -> Dict[str, SecurityPolicyRule]:
        """Gets the organization's security policy."""
        response = self.sdk.settings.get(self.config.org_slug)
        
        if not response.success:
            log.error(f"Failed to get security policy: {response.status}")
            log.error(response.message)
            raise Exception(f"Failed to get security policy: {response.status}, message: {response.message}")
        
        return response.securityPolicyRules

    def create_sbom_output(self, diff: Diff) -> dict:
        """Creates CycloneDX output for a given diff."""
        try:
            result = self.sdk.export.cdx_bom(self.config.org_slug, diff.id)
            if not result.success:
                log.error(f"Failed to get CycloneDX Output for full-scan {diff.id}")
                log.error(result.message)
                return {}

            result.pop("success", None)
            return result
        except Exception as error:
            log.error(f"Unable to get CycloneDX Output for {diff.id}")
            log.error(result.get("message", "No error message provided"))
            return {}

    @staticmethod
    def find_files(path: str) -> List[str]:
        """
        Finds supported manifest files in the given path.
        
        Args:
            path: Path to search for manifest files
            
        Returns:
            List of found manifest file paths
        """
        log.debug("Starting Find Files")
        start_time = time.time()
        files = set()
        
        for ecosystem in socket_globs:
            patterns = socket_globs[ecosystem]
            for file_name in patterns:
                pattern = Core.to_case_insensitive_regex(patterns[file_name]["pattern"])
                file_path = f"{path}/**/{pattern}"
                log.debug(f"Globbing {file_path}")
                glob_start = time.time()
                glob_files = glob(file_path, recursive=True)
                for glob_file in glob_files:
                    if glob_file not in files:
                        files.add(glob_file)
                glob_end = time.time()
                glob_total_time = glob_end - glob_start
                log.debug(f"Glob for pattern {file_path} took {glob_total_time:.2f} seconds")

        log.debug("Finished Find Files")
        end_time = time.time()
        total_time = end_time - start_time
        log.info(f"Found {len(files)} in {total_time:.2f} seconds")
        log.debug(f"Files found: {list(files)}")
        return list(files)
    
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
    def load_files_for_sending(files: List[str], workspace: str) -> List[Tuple[str, Tuple[str, BinaryIO]]]:
        """
        Prepares files for sending to the Socket API.
        
        Args:
            files: List of file paths from find_files()
            workspace: Base directory path to make paths relative to
            
        Returns:
            List of tuples formatted for requests multipart upload:
            [(field_name, (filename, file_object)), ...]
        """
        send_files = []
        
        for file_path in files:
            if "/" in file_path:
                _, name = file_path.rsplit("/", 1)
            else:
                name = file_path
            
            if file_path.startswith(workspace):
                key = file_path[len(workspace):]
            else:
                key = file_path
            
            key = key.lstrip("/")
            key = key.lstrip("./")
            
            f = open(file_path, 'rb')
            payload = (key, (name, f))
            send_files.append(payload)
            
        return send_files

    def create_full_scan(self, files: List[str], params: FullScanParams, store_results: bool = True) -> FullScan:
        """Creates a new full scan via the Socket API."""
        log.debug("Creating new full scan")
        create_full_start = time.time()

        # Time the post API call
        post_start = time.time()

        res = self.sdk.fullscans.post(files, params)
        post_end = time.time()
        log.debug(f"API fullscans.post took {post_end - post_start:.2f} seconds")

        if not res.success:
            log.error(f"Error creating full scan: {res.message}, status: {res.status}")
            raise Exception(f"Error creating full scan: {res.message}, status: {res.status}")

        full_scan = FullScan(**asdict(res.data))
        
        if not store_results:
            log.debug("Skipping results storage as requested")
            full_scan.sbom_artifacts = []
            full_scan.packages = {}
            return full_scan

        # Add extensive debug logging
        log.debug(f"Full scan created with ID: {full_scan.id}")
        log.debug(f"Organization slug: {self.config.org_slug}")
        log.debug(f"store_results is {store_results}")
        log.debug(f"Params used for scan: {params}")
        
        # Time the stream API call
        stream_start = time.time()
        log.debug(f"Initiating stream request for full scan {full_scan.id}")
        try:
            artifacts_response = self.sdk.fullscans.stream(self.config.org_slug, full_scan.id)
            log.debug(f"Stream response received: success={artifacts_response.success}")
            if hasattr(artifacts_response, 'status'):
                log.debug(f"Stream response status: {artifacts_response.status}")
            if hasattr(artifacts_response, 'message'):
                log.debug(f"Stream response message: {artifacts_response.message}")
        except Exception as e:
            log.error(f"Exception during stream request: {str(e)}")
            log.error(f"Exception type: {type(e)}")
            raise

        stream_end = time.time()
        log.debug(f"API fullscans.stream took {stream_end - stream_start:.2f} seconds")

        if not artifacts_response.success:
            log.error(f"Failed to get SBOM data for full-scan {full_scan.id}")
            log.error(artifacts_response.message)
            full_scan.sbom_artifacts = []
            full_scan.packages = {}
            return full_scan

        # Store the original SocketArtifact objects
        full_scan.sbom_artifacts = list(artifacts_response.artifacts.values())
        log.debug(f"Retrieved {len(full_scan.sbom_artifacts)} artifacts")
        
        # Create packages dictionary directly from the artifacts
        packages = {}
        top_level_count = {}
        
        log.debug("Starting package processing from artifacts")
        for artifact in artifacts_response.artifacts.values():
            package = Package.from_socket_artifact(artifact)
            if package.id not in packages:
                package.license_text = self.get_package_license_text(package)
                packages[package.id] = package
                
                # Count top-level ancestors in the same pass
                if package.topLevelAncestors:
                    for top_id in package.topLevelAncestors:
                        top_level_count[top_id] = top_level_count.get(top_id, 0) + 1

        # Update transitive counts
        for package in packages.values():
            package.transitives = top_level_count.get(package.id, 0)

        full_scan.packages = packages
        log.debug(f"Processed {len(packages)} packages")

        create_full_end = time.time()
        total_time = create_full_end - create_full_start
        log.debug(f"New Full Scan created in {total_time:.2f} seconds")
        
        return full_scan

    def get_full_scan(self, full_scan_id: str) -> FullScan:
        """
        Get a FullScan object for an existing full scan including sbom_artifacts and packages.
        
        Args:
            full_scan_id: The ID of the full scan to get
            
        Returns:
            The FullScan object with populated artifacts and packages
        """
        full_scan_metadata = self.sdk.fullscans.metadata(self.config.org_slug, full_scan_id)
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
        all_licenses = Licenses()
        license_str = Licenses.make_python_safe(license_raw)
        
        if license_str is not None and hasattr(all_licenses, license_str):
            license_obj = getattr(all_licenses, license_str)
            return license_obj.licenseText
        
        return ""

    def get_repo_info(self, repo_slug: str) -> RepositoryInfo:
        """
        Gets repository information from the Socket API.
        
        Args:
            repo_slug: Repository slug to get info for
            
        Returns:
            RepositoryInfo object
            
        Raises:
            Exception: If API request fails
        """
        response = self.sdk.repos.repo(self.config.org_slug, repo_slug)
        if not response.success:
            log.error(f"Failed to get repository: {response.status}")
            log.error(response.message)
            raise Exception(f"Failed to get repository info: {response.status}, message: {response.message}")
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

    def get_added_and_removed_packages(self, head_full_scan_id: Optional[str], new_full_scan: FullScan) -> Tuple[Dict[str, Package], Dict[str, Package]]:
        """Get packages that were added and removed between scans."""
        if head_full_scan_id is None:
            log.info(f"No head scan found. New scan ID: {new_full_scan.id}")
            return new_full_scan.packages, {}
            
        log.info(f"Comparing scans - Head scan ID: {head_full_scan_id}, New scan ID: {new_full_scan.id}")
        
        # Time the stream_diff API call
        diff_start = time.time()
        diff_report = self.sdk.fullscans.stream_diff(self.config.org_slug, head_full_scan_id, new_full_scan.id).data
        diff_end = time.time()
        log.debug(f"API fullscans.stream_diff took {diff_end - diff_start:.2f} seconds")
        
        log.info(f"Diff report artifact counts:")
        log.info(f"Added: {len(diff_report.artifacts.added)}")
        log.info(f"Removed: {len(diff_report.artifacts.removed)}")
        log.info(f"Unchanged: {len(diff_report.artifacts.unchanged)}")
        log.info(f"Replaced: {len(diff_report.artifacts.replaced)}")
        log.info(f"Updated: {len(diff_report.artifacts.updated)}")

        added_packages: Dict[str, Package] = {}
        removed_packages: Dict[str, Package] = {}

        # Process added and updated artifacts
        for artifact in chain(diff_report.artifacts.added, diff_report.artifacts.updated):
            try:
                pkg = Package.from_diff_artifact(artifact)
                added_packages[artifact.id] = pkg
            except KeyError as e:
                log.error(f"KeyError creating package from added artifact {artifact.id}: {e}")
                log.error(f"Artifact: name={artifact.name}, version={artifact.version}")

        # Process removed and replaced artifacts
        for artifact in chain(diff_report.artifacts.removed, diff_report.artifacts.replaced):
            try:
                pkg = Package.from_diff_artifact(artifact)
                removed_packages[artifact.id] = pkg
            except KeyError as e:
                log.error(f"KeyError creating package from removed artifact {artifact.id}: {e}")
                log.error(f"Artifact: name={artifact.name}, version={artifact.version}")

        return added_packages, removed_packages

    def create_new_diff(
            self,
            path: str,
            params: FullScanParams,
            no_change: bool = False
    ) -> Diff:
        """Create a new diff using the Socket SDK."""
        log.debug(f"starting create_new_diff with no_change: {no_change}")
        if no_change:
            return Diff(id="no_diff_id")

        # Find manifest files
        files = self.find_files(path)
        files_for_sending = self.load_files_for_sending(files, path)

        log.debug(f"files: {files} found at path {path}")
        if not files:
            return Diff(id="no_diff_id")

        # Initialize head scan ID
        head_full_scan_id = None
        try:
            # Get head scan ID
            head_full_scan_id = self.get_head_scan_for_repo(params.repo)
        except APIResourceNotFound:
            pass

        # Create new scan - only store results if we don't have a head scan to diff against
        if head_full_scan_id is None:
            log.debug("No head scan found to diff against")
        new_full_scan = self.create_full_scan(files_for_sending, params, store_results=head_full_scan_id is None)

        added_packages, removed_packages = self.get_added_and_removed_packages(head_full_scan_id, new_full_scan)

        diff = self.create_diff_report(added_packages, removed_packages)

        base_socket = "https://socket.dev/dashboard/org"
        diff.id = new_full_scan.id
        diff.report_url = f"{base_socket}/{self.config.org_slug}/sbom/{diff.id}"
        if head_full_scan_id is not None:
            diff.diff_url = f"{base_socket}/{self.config.org_slug}/diff/{diff.id}/{head_full_scan_id}"
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

        # Process added packages
        for package_id, package in added_packages.items():
            # Calculate source data once per package
            package.introduced_by = self.get_source_data(package, added_packages)
            
            if not direct_only or package.direct:
                base_purl = f"{package.type}/{package.name}@{package.version}"
                if base_purl not in seen_new_packages:
                    purl = Core.create_purl(package_id, added_packages)
                    diff.new_packages.append(purl)
                    seen_new_packages.add(base_purl)

            self.add_package_alerts_to_collection(
                package=package,
                alerts_collection=alerts_in_added_packages
            )

        # Process removed packages
        for package_id, package in removed_packages.items():
            # Calculate source data once per package
            package.introduced_by = self.get_source_data(package, removed_packages)
            
            if not direct_only or package.direct:
                base_purl = f"{package.type}/{package.name}@{package.version}"
                if base_purl not in seen_removed_packages:
                    purl = Core.create_purl(package_id, removed_packages)
                    diff.removed_packages.append(purl)
                    seen_removed_packages.add(base_purl)

            self.add_package_alerts_to_collection(
                package=package,
                alerts_collection=alerts_in_removed_packages
            )

        diff.new_alerts = Core.get_new_alerts(
            alerts_in_added_packages,
            alerts_in_removed_packages
        )

        diff.new_capabilities = Core.get_capabilities_for_added_packages(added_packages)
        Core.add_purl_capabilities(diff)

        return diff

    @staticmethod
    def create_purl(package_id: str, packages: dict[str, Package]) -> Purl:
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
            purl=package.purl
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
            if package.manifestFiles:
                for manifest_data in package.manifestFiles:
                    manifest_file = manifest_data["file"]
                    if manifest_file:
                        manifests += f"{manifest_file};"
                manifests = manifests.rstrip(";")
            source = ("direct", manifests)
            introduced_by.append(source)
        else:
            for top_id in package.topLevelAncestors or []:
                top_package = packages.get(top_id)
                if top_package:
                    manifests = ""
                    top_purl = f"{top_package.type}/{top_package.name}@{top_package.version}"
                    if top_package.manifestFiles:
                        for manifest_data in top_package.manifestFiles:
                            manifest_file = manifest_data["file"]
                            if manifest_file:
                                manifests += f"{manifest_file};"
                        manifests = manifests.rstrip(";")
                    source = (top_purl, manifests)
                    introduced_by.append(source)
                else:
                    log.debug(f"Unable to get top level package info for {top_id}")

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

    def add_package_alerts_to_collection(self, package: Package, alerts_collection: dict) -> None:
        """Processes alerts from a package and adds them to a shared alerts collection."""
        default_props = type('EmptyProps', (), {
            'description': "",
            'title': "",
            'suggestion': "",
            'nextStepTitle': ""
        })()

        for alert in package.alerts:
            if alert.type == 'licenseSpdxDisj':
                continue

            props = getattr(self.config.all_issues, alert.type, default_props)

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
                title=props.title,
                suggestion=props.suggestion,
                next_step_title=props.nextStepTitle,
                introduced_by=package.introduced_by,  
                purl=package.purl,
                url=package.url
            )

            if alert.type in self.config.security_policy:
                action = self.config.security_policy[alert.type]['action']
                setattr(issue_alert, action, True)

            if alert.key not in alerts_collection:
                alerts_collection[alert.key] = [issue_alert]
            else:
                alerts_collection[alert.key].append(issue_alert)

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
    def has_manifest_files(files: list) -> bool:
        """
        Checks if any files in the list are supported manifest files.
        
        Args:
            files: List of file paths to check
            
        Returns:
            True if any files match manifest patterns, False otherwise
        """
        for ecosystem in socket_globs:
            patterns = socket_globs[ecosystem]
            for file_name in patterns:
                pattern = patterns[file_name]["pattern"]
                for file in files:
                    if "\\" in file:
                        file = file.replace("\\", "/")
                    if PurePath(file).match(pattern):
                        return True
        return False

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
                    alert_str = f"{alert.purl},{alert.manifests},{alert.type}"
                    
                    if alert.error or alert.warn:
                        if alert_str not in consolidated_alerts:
                            alerts.append(alert)
                            consolidated_alerts.add(alert_str)
            else:
                new_alerts = added_package_alerts[alert_key]
                removed_alerts = removed_package_alerts[alert_key]
                
                for alert in new_alerts:
                    alert_str = f"{alert.purl},{alert.manifests},{alert.type}"
                    
                    # Only add if:
                    # 1. Alert isn't in removed packages (or we're not ignoring readded alerts)
                    # 2. We haven't already recorded this alert
                    # 3. It's an error or warning
                    if (not ignore_readded or alert not in removed_alerts) and alert_str not in consolidated_alerts:
                        if alert.error or alert.warn:
                            alerts.append(alert)
                            consolidated_alerts.add(alert_str)

        return alerts


