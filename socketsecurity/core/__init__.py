import logging
import time
from glob import glob
from pathlib import PurePath
from typing import Dict, List, Tuple, Optional

from socketdev import socketdev
from socketdev.fullscans import (
    DiffArtifacts,
    DiffArtifact,
    SecurityCapabilities,
    Alert as SDKAlert,  # To distinguish from our Alert class
    FullScanDiffReport
)

from socketdev.org import Organization

from socketsecurity import __version__
from socketsecurity.core.classes import Diff, FullScan, FullScanParams, Issue, Package, Purl, Report, Repository
from socketsecurity.core.exceptions import (
    APIResourceNotFound,
)



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

    config: SocketConfig
    sdk: socketdev
    def __init__(self, config: SocketConfig, sdk: socketdev) -> None:
        self.config = config
        self.sdk = sdk
        self.set_org_vars()


    def set_org_vars(self) -> None:
        """Sets the main shared configuration variables"""
        # Get org details
        org_id, org_slug = self.get_org_id_slug()

        # Update config with org details FIRST
        self.config.org_id = org_id
        self.config.org_slug = org_slug

        # Set paths
        base_path = f"orgs/{org_slug}"
        self.config.full_scan_path = f"{base_path}/full-scans"
        self.config.repository_path = f"{base_path}/repos"

        # Get security policy AFTER org_id is updated
        self.config.security_policy = self.get_security_policy()

    def get_org_id_slug(self) -> Tuple[str, str]:
        """Gets the Org ID and Org Slug for the API Token"""
        response = self.sdk.org.get()
        organizations: Dict[str, Organization] = response.get("organizations", {})

        if len(organizations) == 1:
            org_id = next(iter(organizations))  # More Pythonic way to get first key
            return org_id, organizations[org_id]['slug']
        return None, None

    def get_sbom_data(self, full_scan_id: str) -> list:
        """
        Return the list of SBOM artifacts for a full scan
        """

        response = self.sdk.fullscans.stream(self.config.org_slug, full_scan_id)
        if(response.get("success", False) == False):
            log.debug(f"Failed to get SBOM data for full-scan {full_scan_id}")
            log.debug(response.get("message", "No message"))
            return []

        response.pop("success", None)
        response.pop("status", None)
        return response

    def get_security_policy(self) -> dict:
        """Get the Security policy"""

        response = self.sdk.settings.get(self.config.org_slug)

        data = response.get("securityPolicyRules", {})
        return data

    @staticmethod
    def old_get_manifest_files(package: Package, packages: dict) -> str:
        if package.direct:
            manifests = []
            for manifest_item in package.manifestFiles:
                manifest = manifest_item["file"]
                manifests.append(manifest)
            manifest_files = ";".join(manifests)
        else:
            manifests = []
            for top_id in package.topLevelAncestors:
                top_package: Package
                top_package = packages[top_id]
                for manifest_item in top_package.manifestFiles:
                    manifest = manifest_item["file"]
                    new_string = f"{package.name}@{package.version}({manifest})"
                    manifests.append(new_string)
            manifest_files = ";".join(manifests)
        return manifest_files

    @staticmethod
    def get_manifest_files(artifact: DiffArtifact, is_head: bool = True) -> str:
        """Gets formatted manifest files string for a package.

        Args:
            artifact: The DiffArtifact containing package data
            is_head: True to use head (new) scan data, False for base (old) scan
        """
        ref = artifact["head"] if is_head else artifact["base"]

        if ref["direct"]:
            # Direct dependency - just list manifest files
            manifests = [m["file"] for m in artifact.get("manifestFiles", [])]
            return ";".join(manifests)

        # Indirect dependency - include package name/version with each manifest
        manifests = []
        for ancestor in ref.get("toplevelAncestors", []):
            # Format: package@version(manifest)
            manifest_str = f"{artifact['name']}@{artifact['version']}({ancestor})"
            manifests.append(manifest_str)

        return ";".join(manifests)

    def create_sbom_output(self, diff: Diff) -> dict:
        try:
            result = self.sdk.export.cdx_bom(self.config.org_slug, diff.id)
            if(result.get("success", False) == False):
                log.error(f"Failed to get CycloneDX Output for full-scan {diff.id}")
                log.error(result.get("message", "No message"))
                return {}

            result.pop("success", None)
            return result
        except Exception as error:
            log.error(f"Unable to get CycloneDX Output for {diff.id}")
            log.error(error)
            sbom = {}
        return sbom

    @staticmethod
    def find_files(path: str) -> List[str]:
        """
        Globs the path for supported manifest files.
        Note: Might move the source to a JSON file
        :param path: Str - path to where the manifest files are located
        :return:
        """
        log.debug("Starting Find Files")
        start_time = time.time()
        files = set()
        for ecosystem in socket_globs:
            patterns = socket_globs[ecosystem]
            for file_name in patterns:
                pattern = patterns[file_name]["pattern"]
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
        return list(files)

    def create_full_scan(self, files: List[str], params: FullScanParams, workspace: str) -> FullScan:
        """
        Calls the full scan API to create a new Full Scan
        :param files: list - Globbed files of manifest files
        :param params: FullScanParams - Set of query params to pass to the endpoint
        :param workspace: str - Path of workspace
        :return:
        """

        create_full_start = time.time()
        log.debug("Creating new full scan")
        params.org_slug = self.config.org_slug
        res = self.sdk.fullscans.post(files, params)

        # If the response is a string, it's an error message
        if isinstance(res, str):
            log.error(f"Error creating full scan: {res}")
            return FullScan()

        full_scan = FullScan(**res)
        full_scan.sbom_artifacts = self.get_sbom_data(full_scan.id)
        create_full_end = time.time()
        total_time = create_full_end - create_full_start
        log.debug(f"New Full Scan created in {total_time:.2f} seconds")
        return full_scan

    def get_head_scan_for_repo(self, repo_slug: str) -> str:
        """Get the head scan ID for a repository"""
        print(f"\nGetting head scan for repo: {repo_slug}")

        response = self.sdk.repos.repo(self.config.org_slug, repo_slug)
        response_data = response.json()
        print(f"Raw API Response: {response_data}")  # Debug raw response

        if not response_data or "repository" not in response_data:
            log.error("Failed to get repository data from API")
            return ""

        repository = Repository(**response_data["repository"])
        print(f"Created repository object: {repository.__dict__}")  # Debug final object

        return repository.head_full_scan_id

    # TODO: this is the same as get_sbom_data. AND IT CALLS GET_SBOM_DATA. huh?
    def get_full_scan(self, full_scan_id: str) -> FullScan:
        """
        Get the specified full scan and return a FullScan object
        :param full_scan_id: str - ID of the full scan to pull
        :return:
        """
        results = self.get_sbom_data(full_scan_id)
        full_scan = FullScan(**results)
        return full_scan

    def old_create_new_diff(self, path: str, params: FullScanParams, workspace: str, no_change: bool = False) -> Diff:
        """Creates a new diff by comparing a new scan against the head scan of a repository.

        Args:
            path: Path to the directory containing files to scan
            params: Parameters for the full scan including repo, branch, commit details
            workspace: Working directory path
            no_change: If True, returns an empty diff without scanning

        Returns:
            Diff: A diff object with one of:
                - id="no_diff_id" if no_change=True or no files found
                - New scan with report_url=diff_url if no head scan exists or repository not found
                - New scan compared against head scan with separate report_url and diff_url
        """
        start_time = time.time()
        log.info(f"Starting new diff for {params.repo}")

        # Return empty diff if no changes requested
        if no_change:
            log.info("No change requested, returning empty diff")
            return Diff(id="no_diff_id")

        # Return empty diff if no files to scan
        files = self.find_files(path)
        if not files:
            log.info("No files found to scan, returning empty diff")
            return Diff(id="no_diff_id")

        # Get head scan ID for the repository
        try:
            head_full_scan_id = self.get_head_scan_for_repo(params.repo)
        except APIResourceNotFound:
            log.info("Repository not found, creating new scan without comparison")
            head_full_scan_id = None

        # Create new scan with no comparison if no head scan exists
        if not head_full_scan_id:
            log.info("No head scan found, creating new scan without comparison")
            new_scan = self.create_full_scan(path, params, workspace)
            base_url = f"https://socket.dev/dashboard/org/{self.config.org_slug}"
            diff = Diff(
                id=new_scan.id,
                report_url=f"{base_url}/sbom/{new_scan.id}",
                diff_url=f"{base_url}/sbom/{new_scan.id}"
            )
        else:
            # Create new scan and compare against head scan
            log.info(f"Creating new scan and comparing against head scan {head_full_scan_id}")
            new_scan = self.create_full_scan(path, params, workspace)
            base_url = f"https://socket.dev/dashboard/org/{self.config.org_slug}"
            diff = Diff(
                id=new_scan.id,
                report_url=f"{base_url}/sbom/{new_scan.id}",
                diff_url=f"{base_url}/diff/{new_scan.id}/{head_full_scan_id}"
            )

        end_time = time.time()
        duration = end_time - start_time
        log.info(f"Completed diff creation in {duration:.2f} seconds")
        return diff

    def create_new_diff(
            self,
            path: str,
            params: FullScanParams,
            workspace: str,
            no_change: bool = False
    ) -> Diff:
        """Create a new diff using the Socket SDK.

        Args:
            path: Path to look for manifest files
            params: Query params for the Full Scan endpoint
            workspace: Path for workspace
            no_change: If True, return empty diff
        """
        if no_change:
            return Diff(id="no_diff_id")

        # Find manifest files
        files = self.find_files(path)
        if not files:
            return Diff(id="no_diff_id")

        try:
            # Get head scan ID
            head_full_scan_id = self.get_head_scan_for_repo(params.repo)
        except APIResourceNotFound:
            head_full_scan_id = None

        # Create new scan and get diff report
        new_scan_start = time.time()
        new_full_scan = self.create_full_scan(files, params, workspace)

        # Get diff report from SDK
        diff_report = self.sdk.fullscans.stream_diff(self.config.org_slug, head_full_scan_id, new_full_scan.id)
        new_scan_end = time.time()
        log.info(f"Total time to get diff report: {new_scan_end - new_scan_start:.2f}")

        # Transform DiffArtifacts into Diff
        diff = Diff()
        diff.id = new_full_scan.id

        # Compare capabilities and alerts
        capabilities = Core.compare_capabilities(diff_report["artifacts"])
        alerts = Core.compare_issue_alerts(diff_report["artifacts"])

        # Set URLs
        base_socket = "https://socket.dev/dashboard/org"
        diff.report_url = f"{base_socket}/{self.config.org_slug}/sbom/{diff.id}"
        if head_full_scan_id:
            diff.diff_url = f"{base_socket}/{self.config.org_slug}/diff/{diff.id}/{head_full_scan_id}"
        else:
            diff.diff_url = diff.report_url

        # Set final properties
        diff.new_alerts = alerts
        diff.new_capabilities = capabilities
        diff.packages = diff_report["artifacts"]  # Store full artifacts for reference

        return diff

    def old_compare_sboms(self, new_scan: list, head_scan: list) -> Diff:
        """
        compare the SBOMs of the new full Scan and the head full scan. Return a Diff report with new packages,
        removed packages, and new alerts for the new full scan compared to the head.
        :param new_scan: FullScan - Newly created FullScan for this execution
        :param head_scan: FullScan - Current head FullScan for the repository
        :return:
        """
        diff: Diff
        diff = Diff()
        new_packages = Core.create_sbom_dict(new_scan)
        head_packages = Core.create_sbom_dict(head_scan)
        new_scan_alerts = {}
        head_scan_alerts = {}
        consolidated = set()
        for package_id in new_packages:
            purl, package = Core.create_purl(package_id, new_packages)
            base_purl = f"{purl.ecosystem}/{purl.name}@{purl.version}"
            if package_id not in head_packages and package.direct and base_purl not in consolidated:
                diff.new_packages.append(purl)
                consolidated.add(base_purl)
            new_scan_alerts = self.create_issue_alerts(package, new_scan_alerts, new_packages)
        for package_id in head_packages:
            purl, package = Core.create_purl(package_id, head_packages)
            if package_id not in new_packages and package.direct:
                diff.removed_packages.append(purl)
            head_scan_alerts = self.create_issue_alerts(package, head_scan_alerts, head_packages)
        diff.new_alerts = Core.compare_issue_alerts(new_scan_alerts, head_scan_alerts, diff.new_alerts)
        diff.new_capabilities = Core.compare_capabilities(new_packages, head_packages)
        diff = Core.add_capabilities_to_purl(diff)
        return diff

    @staticmethod
    def compare_sboms(diff_artifacts: DiffArtifacts) -> dict:
        """Compare SBOMs using the new DiffArtifacts structure.

        Args:
            diff_artifacts: DiffArtifacts containing added/removed/replaced/updated packages
        """
        # Get new capabilities across all changed artifacts
        capabilities = Core.compare_capabilities(diff_artifacts)

        # Add capabilities to artifacts
        diff_artifacts = Core.add_capabilities_to_purl(diff_artifacts, capabilities)

        # Get new alerts across all changed artifacts
        alerts = Core.compare_issue_alerts(diff_artifacts)

        return {
            "new_packages": diff_artifacts["added"],
            "removed_packages": diff_artifacts["removed"],
            "updated_packages": diff_artifacts["updated"],
            "replaced_packages": diff_artifacts["replaced"],
            "new_alerts": alerts,
            "new_capabilities": capabilities
        }

    @staticmethod
    def old_add_capabilities_to_purl(diff: Diff) -> None:
        """Adds capability information to each purl in the diff's new_packages list."""
        diff.new_packages = [
            Purl(
                **{**purl.__dict__,
                "capabilities": diff.new_capabilities.get(purl.id, [])}
            )
            if purl.id in diff.new_capabilities and diff.new_capabilities[purl.id]
            else purl
            for purl in diff.new_packages
        ]

    @staticmethod
    def add_capabilities_to_purl(
        diff_artifacts: DiffArtifacts,
        capabilities: Dict[str, List[str]]
    ) -> DiffArtifacts:
        """Add capability information to DiffArtifacts."""
        # Process added artifacts
        for artifact in diff_artifacts["added"]:
            if artifact["id"] in capabilities:
                artifact["capabilities_list"] = capabilities[artifact["id"]]

        # Process updated/replaced artifacts
        for artifact in diff_artifacts["updated"] + diff_artifacts["replaced"]:
            if artifact["id"] in capabilities:
                artifact["capabilities_list"] = capabilities[artifact["id"]]

        return diff_artifacts

    @staticmethod
    def old_compare_capabilities(new_packages: dict, head_packages: dict) -> dict:
        capabilities = {}
        for package_id in new_packages:
            package: Package
            head_package: Package
            package = new_packages[package_id]
            if package_id in head_packages:
                head_package = head_packages[package_id]
                for alert in package.alerts:
                    if alert not in head_package.alerts:
                        capabilities = Core.check_alert_capabilities(package, capabilities, package_id, head_package)
            else:
                capabilities = Core.check_alert_capabilities(package, capabilities, package_id)

        return capabilities


    @staticmethod
    def compare_capabilities(diff_artifacts: DiffArtifacts) -> Dict[str, List[str]]:
        """Compare capabilities across DiffArtifacts to find new capabilities.

        Returns:
            Dict mapping package IDs to lists of capability strings
        """
        capabilities: Dict[str, List[str]] = {}

        # Process added artifacts (all capabilities are new)
        for artifact in diff_artifacts["added"]:
            caps = []
            if artifact["capabilities"]["env"]: caps.append("Environment")
            if artifact["capabilities"]["net"]: caps.append("Network")
            if artifact["capabilities"]["fs"]: caps.append("File System")
            if artifact["capabilities"]["shell"]: caps.append("Shell")
            if caps:
                capabilities[artifact["id"]] = caps

        # Process updated/replaced artifacts (compare with base)
        for artifact in diff_artifacts["updated"] + diff_artifacts["replaced"]:
            base_caps = artifact["base"]["capabilities"]
            head_caps = artifact["capabilities"]

            new_caps = []
            if head_caps["env"] and not base_caps["env"]: new_caps.append("Environment")
            if head_caps["net"] and not base_caps["net"]: new_caps.append("Network")
            if head_caps["fs"] and not base_caps["fs"]: new_caps.append("File System")
            if head_caps["shell"] and not base_caps["shell"]: new_caps.append("Shell")

            if new_caps:
                capabilities[artifact["id"]] = new_caps

        return capabilities
    # Move to constants/config
    ALERT_TYPE_TO_CAPABILITY = {
        "envVars": "Environment",
        "networkAccess": "Network",
        "filesystemAccess": "File System",
        "shellAccess": "Shell"
    }

    @staticmethod
    def old_check_alert_capabilities(
            package: Package,
            capabilities: dict,
            package_id: str,
            head_package: Package = None
    ) -> dict:
        """Moving original implementation to old_ prefix.
        Note: This is no longer needed as capabilities come directly from DiffArtifact["capabilities"]
        """

        for alert in package.alerts:
            new_alert = True
            if head_package is not None and alert in head_package.alerts:
                new_alert = False

            # Support both dictionary and Alert object access
            alert_type = alert.type if hasattr(alert, 'type') else alert["type"]

            if alert_type in Core.ALERT_TYPE_TO_CAPABILITY and new_alert:
                value = Core.ALERT_TYPE_TO_CAPABILITY[alert_type]
                if package_id not in capabilities:
                    capabilities[package_id] = [value]
                else:
                    if value not in capabilities[package_id]:
                        capabilities[package_id].append(value)
        return capabilities

    @staticmethod
    def old_compare_issue_alerts(new_scan_alerts: dict, head_scan_alerts: dict, alerts: list) -> list:
        """
        Compare the issue alerts from the new full scan and the head full scans. Return a list of new alerts that
        are in the new full scan and not in the head full scan
        :param new_scan_alerts: dictionary of alerts from the new full scan
        :param head_scan_alerts: dictionary of alerts from the new head scan
        :param alerts: List of new alerts that are only in the new Full Scan
        :return:
        """
        consolidated_alerts = []
        for alert_key in new_scan_alerts:
            if alert_key not in head_scan_alerts:
                new_alerts = new_scan_alerts[alert_key]
                for alert in new_alerts:
                    alert: Issue
                    alert_str = f"{alert.purl},{alert.manifests},{alert.type}"
                    if alert.error or alert.warn:
                        if alert_str not in consolidated_alerts:
                            alerts.append(alert)
                            consolidated_alerts.append(alert_str)
            else:
                new_alerts = new_scan_alerts[alert_key]
                head_alerts = head_scan_alerts[alert_key]
                for alert in new_alerts:
                    alert: Issue
                    alert_str = f"{alert.purl},{alert.manifests},{alert.type}"
                    if alert not in head_alerts and alert_str not in consolidated_alerts:
                        if alert.error or alert.warn:
                            alerts.append(alert)
                            consolidated_alerts.append(alert_str)
        return alerts

    @staticmethod
    def compare_issue_alerts(diff_artifacts: DiffArtifacts) -> list[Issue]:
        alerts = []
        consolidated_alerts = set()

        # Process added artifacts (all alerts are new)
        for artifact in diff_artifacts["added"]:
            purl = Core.create_purl(artifact)
            for alert in artifact["alerts"]:
                alert_str = f"{purl.purl},{alert.get('file', '')},{alert['type']},{alert['key']}"
                if alert_str not in consolidated_alerts:
                    alerts.append(alert)
                    consolidated_alerts.add(alert_str)

        # Process updated and replaced artifacts (compare with base)
        for artifact in diff_artifacts["updated"] + diff_artifacts["replaced"]:
            base_alerts = {
                (a.get('file', ''), a['type'], a['key'])
                for a in artifact["base"].get("alerts", [])
            }

            for alert in artifact["alerts"]:
                alert_tuple = (alert.get('file', ''), alert['type'], alert['key'])
                if alert_tuple not in base_alerts:
                    purl = Core.create_purl(artifact)
                    alert_str = f"{purl.purl},{alert.get('file', '')},{alert['type']},{alert['key']}"
                    if alert_str not in consolidated_alerts:
                        alerts.append(alert)
                        consolidated_alerts.add(alert_str)

        return alerts

    def old_create_issue_alerts(self, package: Package, alerts: dict, packages: dict) -> dict:
        """Create issue alerts for a package"""
        for alert in package.alerts:
            if not hasattr(self.config.all_issues, alert.type):
                continue
            props = getattr(self.config.all_issues, alert.type)
            introduced_by = self.get_source_data(package, packages)
            suggestion = getattr(props, 'suggestion', None)
            next_step_title = getattr(props, 'nextStepTitle', None)
            issue_alert = Issue(
                key=alert.key,
                type=alert.type,
                severity=alert.severity,
                description=props.description,
                title=props.title,
                suggestion=suggestion,
                next_step_title=next_step_title,
                introduced_by=introduced_by,
                purl=package.purl,
                url=package.url
            )
            if alert.type in self.config.security_policy:
                action = self.config.security_policy[alert.type]['action']
                setattr(issue_alert, action, True)
            if issue_alert.type != 'licenseSpdxDisj':
                if issue_alert.key not in alerts:
                    alerts[issue_alert.key] = [issue_alert]
                else:
                    alerts[issue_alert.key].append(issue_alert)
        return alerts

    def create_issue_alerts(self, artifact: DiffArtifact, alerts: dict, is_head: bool = True) -> dict:
        """Create issue alerts for a package"""
        for alert in artifact["alerts"]:
            if not hasattr(self.config.all_issues, alert["type"]):
                continue

            props = getattr(self.config.all_issues, alert["type"])
            introduced_by = self.get_source_data(artifact, is_head)

            issue_alert = Issue(
                key=alert["key"],
                type=alert["type"],
                severity=alert.get("severity", ""),
                description=props.description,
                title=props.title,
                suggestion=getattr(props, 'suggestion', None),
                next_step_title=getattr(props, 'nextStepTitle', None),
                introduced_by=introduced_by,
                purl=f"{artifact['type']}/{artifact['name']}@{artifact['version']}",
                url=artifact.get("url", "")
            )

            if alert["type"] in self.config.security_policy:
                action = self.config.security_policy[alert["type"]]['action']
                setattr(issue_alert, action, True)

            if issue_alert.type != 'licenseSpdxDisj':
                alerts.setdefault(issue_alert.key, []).append(issue_alert)

        return alerts

    @staticmethod
    def old_get_source_data(package: Package, packages: dict) -> list:
        """
        Creates the properties for source data of the source manifest file(s) and top level packages.
        :param package: Package - Current package being evaluated
        :param packages: Dict - All packages, used to determine top level package information for transitive packages
        :return:
        """
        introduced_by = []
        if package.direct:
            manifests = ""
            for manifest_data in package.manifestFiles:
                manifest_file = manifest_data.get("file")
                manifests += f"{manifest_file};"
            manifests = manifests.rstrip(";")
            source = ("direct", manifests)
            introduced_by.append(source)
        else:
            for top_id in package.topLevelAncestors:
                top_package: Package
                top_package = packages[top_id]
                manifests = ""
                top_purl = f"{top_package.type}/{top_package.name}@{top_package.version}"
                for manifest_data in top_package.manifestFiles:
                    manifest_file = manifest_data.get("file")
                    manifests += f"{manifest_file};"
                manifests = manifests.rstrip(";")
                source = (top_purl, manifests)
                introduced_by.append(source)
        return introduced_by

    @staticmethod
    def get_source_data(artifact: DiffArtifact, is_head: bool = True) -> List[Tuple[str, str]]:
        """Creates source data showing how a package was introduced."""
        dep_ref = artifact["head"] if is_head else artifact["base"]

        if dep_ref["direct"]:
            return [("direct", artifact["files"])]

        # For indirect deps, we need to maintain the same format for CLI output
        return [
            (f"{artifact['type']}/{ancestor}", artifact["files"])
            for ancestor in dep_ref["toplevelAncestors"]
        ]

    @staticmethod
    def old_create_purl(package_id: str, packages: dict) -> (Purl, Package):
        """
        Creates the extended PURL data to use in the added or removed package details. Primarily used for outputting
        data in the results for detections.
        :param package_id: Str - Package ID of the package to create the PURL data
        :param packages: dict - All packages to use for look up from transitive packages
        :return:
        """
        package: Package
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
        return purl, package

    @staticmethod
    def create_purl(artifact: DiffArtifact, is_head: bool = True) -> Purl:
        """Creates a Purl object from a DiffArtifact.

        Args:
            artifact: The DiffArtifact containing package data
            is_head: True to use head (new) scan data, False for base (old) scan
        """
        return Purl(
            id=artifact["id"],
            name=artifact["name"],
            version=artifact["version"],
            ecosystem=artifact["type"],
            direct=artifact["head"]["direct"] if is_head else artifact["base"]["direct"],
            introduced_by=Core.get_source_data(artifact, is_head),
            author=artifact.get("author", []),
            size=artifact["size"],
            transitives=0,  # TODO: Do we still need this?
            url=artifact.get("url", ""),
            purl=f"{artifact['type']}/{artifact['name']}@{artifact['version']}"
        )

    @staticmethod
    def save_file(file_name: str, content: str) -> None:
        """Saves content to a file."""
        try:
            with open(file_name, "w") as f:
                f.write(content)
        except IOError as e:
            log.error(f"Failed to save file {file_name}: {e}")
            raise

    # @staticmethod
    # def create_license_file(diff: Diff) -> None:
    #     output = []
    #     for package_id in diff.packages:
    #         purl =  Core.create_purl(package_id, diff.packages)

    @staticmethod
    def has_manifest_files(files: list) -> bool:
        """
        Checks if any files in the list are supported manifest files.
        Returns True if ANY files match our manifest patterns (meaning we need to scan)
        Returns False if NO files match (meaning we can skip scanning)
        """
        for ecosystem in socket_globs:
            patterns = socket_globs[ecosystem]
            for file_name in patterns:
                pattern = patterns[file_name]["pattern"]
                for file in files:
                    if "\\" in file:
                        file = file.replace("\\", "/")
                    if PurePath(file).match(pattern):
                        return True  # Found a manifest file, no need to check further
        return False  # No manifest files found
