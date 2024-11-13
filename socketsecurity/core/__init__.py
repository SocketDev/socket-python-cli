import base64
import json
import logging
import platform
import time
from glob import glob
from pathlib import PurePath
from urllib.parse import urlencode

import requests

from socketsecurity import __version__
from socketsecurity.core.classes import Alert, Diff, FullScan, FullScanParams, Issue, Package, Purl, Report, Repository
from socketsecurity.core.exceptions import (
    APIAccessDenied,
    APICloudflareError,
    APIFailure,
    APIInsufficientQuota,
    APIKeyMissing,
    APIResourceNotFound,
)
from socketsecurity.core.issues import AllIssues
from socketsecurity.core.licenses import Licenses

from .cli_client import CliClient
from .config import SocketConfig
from .utils import socket_globs

__all__ = [
    "Core",
    "log",
    "__version__",
    "do_request"
]


global encoded_key
version = __version__
api_url = "https://api.socket.dev/v0"
timeout = 30
all_issues = AllIssues()
org_id = None
org_slug = None
all_new_alerts = False
allow_unverified_ssl = False
log = logging.getLogger("socketdev")


def encode_key(token: str) -> None:
    """
    encode_key takes passed token string and does a base64 encoding. It sets this as a global variable
    :param token: str of the Socket API Security Token
    :return:
    """
    global encoded_key
    encoded_key = base64.b64encode(token.encode()).decode('ascii')


def do_request(
        path: str,
        headers: dict = None,
        payload: [dict, str] = None,
        files: list = None,
        method: str = "GET",
        base_url: str = None,
) -> requests.request:
    """
    do_requests is the shared function for making HTTP calls
    :param base_url:
    :param path: Required path for the request
    :param headers: Optional dictionary of headers. If not set will use a default set
    :param payload: Optional dictionary or string of the payload to pass
    :param files: Optional list of files to upload
    :param method: Optional method to use, defaults to GET
    :return:
    """

    if base_url is not None:
        url = f"{base_url}/{path}"
    else:
        if encoded_key is None or encoded_key == "":
            raise APIKeyMissing
        url = f"{api_url}/{path}"

    if headers is None:
        headers = {
            'Authorization': f"Basic {encoded_key}",
            'User-Agent': f'SocketPythonCLI/{__version__}',
            "accept": "application/json"
        }
    verify = True
    if allow_unverified_ssl:
        verify = False
    response = requests.request(
        method.upper(),
        url,
        headers=headers,
        data=payload,
        files=files,
        timeout=timeout,
        verify=verify
    )
    output_headers = headers.copy()
    output_headers['Authorization'] = "API_KEY_REDACTED"
    output = {
        "url": url,
        "headers": output_headers,
        "status_code": response.status_code,
        "body": response.text,
        "payload": payload,
        "files": files,
        "timeout": timeout
    }
    log.debug(output)
    if response.status_code <= 399:
        return response
    elif response.status_code == 400:
        raise APIFailure(output)
    elif response.status_code == 401:
        raise APIAccessDenied("Unauthorized")
    elif response.status_code == 403:
        raise APIInsufficientQuota("Insufficient max_quota for API method")
    elif response.status_code == 404:
        raise APIResourceNotFound(f"Path not found {path}")
    elif response.status_code == 429:
        raise APIInsufficientQuota("Insufficient quota for API route")
    elif response.status_code == 524:
        raise APICloudflareError(response.text)
    else:
        msg = {
            "status_code": response.status_code,
            "UnexpectedError": "There was an unexpected error using the API",
            "error": response.text,
            "payload": payload,
            "url": url
        }
        raise APIFailure(msg)


class Core:

    client: CliClient
    config: SocketConfig

    def __init__(self, config: SocketConfig, client: CliClient):
        self.config = config
        self.client = client
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

    def get_org_id_slug(self) -> tuple[str, str]:
        """Gets the Org ID and Org Slug for the API Token"""
        path = "organizations"
        response = self.client.request(path)
        data = response.json()
        organizations = data.get("organizations")
        new_org_id = None
        new_org_slug = None
        if len(organizations) == 1:
            for key in organizations:
                new_org_id = key
                new_org_slug = organizations[key].get('slug')
        return new_org_id, new_org_slug

    def get_sbom_data(self, full_scan_id: str) -> list:
        """
        Return the list of SBOM artifacts for a full scan
        """
        path = f"orgs/{self.config.org_slug}/full-scans/{full_scan_id}"
        response = self.client.request(path)
        results = []

        if response.status_code != 200:
            log.debug(f"Failed to get SBOM data for full-scan {full_scan_id}")
            log.debug(response.text)
            return []
        data = response.text
        data.strip('"')
        data.strip()
        for line in data.split("\n"):
            if line != '"' and line != "" and line is not None:
                item = json.loads(line)
                results.append(item)

        return results

    def get_security_policy(self) -> dict:
        """Get the Security policy and determine the effective Org security policy"""
        payload = [{"organization": self.config.org_id}]

        response = self.client.request(
            path="settings",
            method="POST",
            payload=json.dumps(payload)
        )

        data = response.json()
        defaults = data.get("defaults", {})
        default_rules = defaults.get("issueRules", {})
        entries = data.get("entries", [])

        org_rules = {}

        # Get organization-specific rules
        for org_set in entries:
            settings = org_set.get("settings")
            if settings:
                org_details = settings.get("organization", {})
                org_rules.update(org_details.get("issueRules", {}))

        # Apply default rules where no org-specific rule exists
        for default in default_rules:
            if default not in org_rules:
                action = default_rules[default]["action"]
                org_rules[default] = {"action": action}

        return org_rules

    @staticmethod
    def get_manifest_files(package: Package, packages: dict) -> str:
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

    def create_sbom_output(self, diff: Diff) -> dict:
        base_path = f"orgs/{self.config.org_slug}/export/cdx"
        path = f"{base_path}/{diff.id}"
        result = self.client.request(path=path)
        try:
            sbom = result.json()
        except Exception as error:
            log.error(f"Unable to get CycloneDX Output for {diff.id}")
            log.error(error)
            sbom = {}
        return sbom

    # TODO: verify what this does. It looks like it should be named "all_files_unsupported"
    @staticmethod
    def match_supported_files(files: list) -> bool:
        """
        Checks if any of the files in the list match the supported file patterns
        Returns True if NO files match (meaning no changes to manifest files)
        Returns False if ANY files match (meaning there are manifest changes)
        """
        matched_files = []
        not_matched = False
        for ecosystem in socket_globs:
            patterns = socket_globs[ecosystem]
            for file_name in patterns:
                pattern = patterns[file_name]["pattern"]
                # path_pattern = f"**/{pattern}"
                for file in files:
                    if "\\" in file:
                        file = file.replace("\\", "/")
                    if PurePath(file).match(pattern):
                        matched_files.append(file)
        if len(matched_files) == 0:
            not_matched = True
        return not_matched

    @staticmethod
    def find_files(path: str) -> list:
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

    def create_full_scan(self, files: list, params: FullScanParams, workspace: str) -> FullScan:
        """
        Calls the full scan API to create a new Full Scan
        :param files: list - Globbed files of manifest files
        :param params: FullScanParams - Set of query params to pass to the endpoint
        :param workspace: str - Path of workspace
        :return:
        """
        send_files = []
        create_full_start = time.time()
        log.debug("Creating new full scan")
        for file in files:
            if platform.system() == "Windows":
                file = file.replace("\\", "/")
            if "/" in file:
                path, name = file.rsplit("/", 1)
            else:
                path = "."
                name = file
            full_path = f"{path}/{name}"
            if full_path.startswith(workspace):
                key = full_path[len(workspace):]
            else:
                key = full_path
            key = key.lstrip("/")
            key = key.lstrip("./")
            payload = (
                key,
                (
                    name,
                    open(full_path, 'rb')
                )
            )
            send_files.append(payload)
        query_params = urlencode(params.__dict__)
        full_uri = f"{self.config.full_scan_path}?{query_params}"
        response = self.client.request(full_uri, method="POST", files=send_files)
        results = response.json()
        full_scan = FullScan(**results)
        full_scan.sbom_artifacts = self.get_sbom_data(full_scan.id)
        create_full_end = time.time()
        total_time = create_full_end - create_full_start
        log.debug(f"New Full Scan created in {total_time:.2f} seconds")
        return full_scan

    @staticmethod
    def get_license_details(package: Package) -> Package:
        license_raw = package.license
        all_licenses = Licenses()
        license_str = Licenses.make_python_safe(license_raw)
        if license_str is not None and hasattr(all_licenses, license_str):
            license_obj = getattr(all_licenses, license_str)
            package.license_text = license_obj.licenseText
        return package

    def get_head_scan_for_repo(self, repo_slug: str) -> str:
        """Get the head scan ID for a repository"""
        print(f"\nGetting head scan for repo: {repo_slug}")
        repo_path = f"{self.config.repository_path}/{repo_slug}"
        print(f"Repository path: {repo_path}")

        response = self.client.request(repo_path)
        response_data = response.json()
        print(f"Raw API Response: {response_data}")  # Debug raw response
        print(f"Response type: {type(response_data)}")  # Debug response type

        if "repository" in response_data:
            print(f"Repository data: {response_data['repository']}")  # Debug repository data
        else:
            print("No 'repository' key in response data!")

        repository = Repository(**response_data["repository"])
        print(f"Created repository object: {repository.__dict__}")  # Debug final object

        return repository.head_full_scan_id

    def get_full_scan(self, full_scan_id: str) -> FullScan:
        """
        Get the specified full scan and return a FullScan object
        :param full_scan_id: str - ID of the full scan to pull
        :return:
        """
        full_scan_url = f"{self.config.full_scan_path}/{full_scan_id}"
        response = self.client.request(full_scan_url)
        results = response.json()
        full_scan = FullScan(**results)
        full_scan.sbom_artifacts = self.get_sbom_data(full_scan.id)
        return full_scan

    def create_new_diff(self, path: str, params: FullScanParams, workspace: str, no_change: bool = False) -> Diff:
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

    def compare_sboms(self, new_scan: list, head_scan: list) -> Diff:
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
    def add_capabilities_to_purl(diff: Diff) -> Diff:
        new_packages = []
        for purl in diff.new_packages:
            purl: Purl
            if purl.id in diff.new_capabilities:
                capabilities = diff.new_capabilities[purl.id]
                if len(capabilities) > 0:
                    purl.capabilities = capabilities
                    new_packages.append(purl)
            else:
                new_packages.append(purl)
        diff.new_packages = new_packages
        return diff

    @staticmethod
    def compare_capabilities(new_packages: dict, head_packages: dict) -> dict:
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
    def check_alert_capabilities(
            package: Package,
            capabilities: dict,
            package_id: str,
            head_package: Package = None
    ) -> dict:
        alert_types = {
            "envVars": "Environment",
            "networkAccess": "Network",
            "filesystemAccess": "File System",
            "shellAccess": "Shell"
        }

        for alert in package.alerts:
            new_alert = True
            if head_package is not None and alert in head_package.alerts:
                new_alert = False

            # Support both dictionary and Alert object access
            alert_type = alert.type if hasattr(alert, 'type') else alert["type"]

            if alert_type in alert_types and new_alert:
                value = alert_types[alert_type]
                if package_id not in capabilities:
                    capabilities[package_id] = [value]
                else:
                    if value not in capabilities[package_id]:
                        capabilities[package_id].append(value)
        return capabilities

    @staticmethod
    def compare_issue_alerts(new_scan_alerts: dict, head_scan_alerts: dict, alerts: list) -> list:
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

    def create_issue_alerts(self, package: Package, alerts: dict, packages: dict) -> dict:
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

    @staticmethod
    def get_source_data(package: Package, packages: dict) -> list:
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
    def create_purl(package_id: str, packages: dict) -> (Purl, Package):
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
    def create_sbom_dict(sbom: list) -> dict:
        """
        Converts the SBOM Artifacts from the FulLScan into a Dictionary for parsing
        :param sbom: list - Raw artifacts for the SBOM
        :return:
        """
        packages = {}
        top_level_count = {}
        for item in sbom:
            package = Package(**item)
            if package.id in packages:
                print("Duplicate package?")
            else:
                package = Core.get_license_details(package)
                packages[package.id] = package
                for top_id in package.topLevelAncestors:
                    if top_id not in top_level_count:
                        top_level_count[top_id] = 1
                    else:
                        top_level_count[top_id] += 1
        if len(top_level_count) > 0:
            for package_id in top_level_count:
                packages[package_id].transitives = top_level_count[package_id]
        return packages

    @staticmethod
    def save_file(file_name: str, content: str) -> None:
        file = open(file_name, "w")
        file.write(content)
        file.close()

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
