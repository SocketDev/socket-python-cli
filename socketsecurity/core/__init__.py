import logging
import requests
from urllib.parse import urlencode
import base64
import json
from socketsecurity.core.exceptions import (
    APIFailure, APIKeyMissing, APIAccessDenied, APIInsufficientQuota, APIResourceNotFound, APICloudflareError
)
from socketsecurity import __version__
from socketsecurity.core.licenses import Licenses
from socketsecurity.core.issues import AllIssues
from socketsecurity.core.classes import (
    Report,
    Issue,
    Package,
    Alert,
    FullScan,
    FullScanParams,
    Repository,
    Diff,
    Purl
)
import platform
from glob import glob
import time

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
full_scan_path = ""
repository_path = ""
all_issues = AllIssues()
org_id = None
org_slug = None
all_new_alerts = False
security_policy = {}
log = logging.getLogger("socketdev")
log.addHandler(logging.NullHandler())


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
    response = requests.request(
        method.upper(),
        url,
        headers=headers,
        data=payload,
        files=files,
        timeout=timeout
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
    token: str
    base_api_url: str
    request_timeout: int
    reports: list

    def __init__(self, token: str, base_api_url=None, request_timeout=None, enable_all_alerts=False):
        self.token = token + ":"
        encode_key(self.token)
        self.socket_date_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        self.base_api_url = base_api_url
        if self.base_api_url is not None:
            Core.set_api_url(self.base_api_url)
        self.request_timeout = request_timeout
        if self.request_timeout is not None:
            Core.set_timeout(self.request_timeout)
        if enable_all_alerts:
            global all_new_alerts
            all_new_alerts = True
        Core.set_org_vars()

    @staticmethod
    def enable_debug_log(level: int):
        global log
        log.setLevel(level)

    @staticmethod
    def set_org_vars() -> None:
        """
        Sets the main shared global variables
        :return:
        """
        global org_id, org_slug, full_scan_path, repository_path, security_policy
        org_id, org_slug = Core.get_org_id_slug()
        base_path = f"orgs/{org_slug}"
        full_scan_path = f"{base_path}/full-scans"
        repository_path = f"{base_path}/repos"
        security_policy = Core.get_security_policy()

    @staticmethod
    def set_api_url(base_url: str):
        """
        Set the global API URl if provided
        :param base_url:
        :return:
        """
        global api_url
        api_url = base_url

    @staticmethod
    def set_timeout(request_timeout: int):
        """
        Set the global Requests timeout
        :param request_timeout:
        :return:
        """
        global timeout
        timeout = request_timeout

    @staticmethod
    def get_org_id_slug() -> (str, str):
        """
        Gets the Org ID and Org Slug for the API Token
        :return:
        """
        path = "organizations"
        response = do_request(path)
        data = response.json()
        organizations = data.get("organizations")
        new_org_id = None
        new_org_slug = None
        if len(organizations) == 1:
            for key in organizations:
                new_org_id = key
                new_org_slug = organizations[key].get('slug')
        return new_org_id, new_org_slug

    @staticmethod
    def get_sbom_data(full_scan_id: str) -> list:
        path = f"orgs/{org_slug}/full-scans/{full_scan_id}"
        response = do_request(path)
        results = []
        try:
            data = response.json()
            results = data.get("sbom_artifacts") or []
        except Exception as error:
            log.debug("Failed with old style full-scan API using new format")
            log.debug(error)
            data = response.text
            data.strip('"')
            data.strip()
            for line in data.split("\n"):
                if line != '"' and line != "" and line is not None:
                    item = json.loads(line)
                    results.append(item)
        return results

    @staticmethod
    def get_security_policy() -> dict:
        """
        Get the Security policy and determine the effective Org security policy
        :return:
        """
        path = "settings"
        payload = [
            {
                "organization": org_id
            }
        ]
        response = do_request(path, payload=json.dumps(payload), method="POST")
        data = response.json()
        defaults = data.get("defaults")
        default_rules = defaults.get("issueRules")
        entries = data.get("entries")
        org_rules = {}
        for org_set in entries:
            settings = org_set.get("settings")
            if settings is not None:
                org_details = settings.get("organization")
                org_rules = org_details.get("issueRules")
        for default in default_rules:
            if default not in org_rules:
                action = default_rules[default]["action"]
                org_rules[default] = {
                    "action": action
                }
        return org_rules

    # @staticmethod
    # def get_supported_file_types() -> dict:
    #     path = "report/supported"

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

    @staticmethod
    def create_sbom_output(diff: Diff) -> list:
        sbom = []
        for package_id in diff.packages:
            package: Package
            package = diff.packages[package_id]
            manifest_files = Core.get_manifest_files(package, diff.packages)
            item = {
                "id": package.id,
                "license": package.license,
                "license_text": package.license_text,
                "manifestFiles": manifest_files,
                "score": package.score,
                "size": package.size,
                "ecosystem": package.type,
                "alerts": package.alerts,
                "direct": package.direct,
                "name": package.name,
                "version": package.version,
                "author": package.author,
                "url": package.url
            }
            sbom.append(item)
        return sbom

    @staticmethod
    def find_files(path: str, new_files: list = None) -> list:
        """
        Globs the path for supported manifest files.
        Note: Might move the source to a JSON file
        :param path: Str - path to where the manifest files are located
        :param new_files:
        :return:
        """
        socket_globs = {
            "npm": {
                "package.json": {
                    "pattern": "package.json"
                },
                "package-lock.json": {
                    "pattern": "package-lock.json"
                },
                "npm-shrinkwrap.json": {
                    "pattern": "npm-shrinkwrap.json"
                },
                "yarn.lock": {
                    "pattern": "yarn.lock"
                },
                "pnpm-lock.yaml": {
                    "pattern": "pnpm-lock.yaml"
                },
                "pnpm-lock.yml": {
                    "pattern": "pnpm-lock.yml"
                },
                "pnpm-workspace.yaml": {
                    "pattern": "pnpm-workspace.yaml"
                },
                "pnpm-workspace.yml": {
                    "pattern": "pnpm-workspace.yml"
                }
            },
            "pypi": {
                "pipfile": {
                    "pattern": "pipfile"
                },
                "pyproject.toml": {
                    "pattern": "pyproject.toml"
                },
                "requirements.txt": {
                    "pattern": "*requirements.txt"
                },
                "requirements": {
                    "pattern": "requirements/*.txt"
                },
                "requirements-*.txt": {
                    "pattern": "requirements-*.txt"
                },
                "requirements_*.txt": {
                    "pattern": "requirements_*.txt"
                },
                "requirements.frozen": {
                    "pattern": "requirements.frozen"
                },
                "setup.py": {
                    "pattern": "setup.py"
                }
            },
            "golang": {
                "go.mod": {
                    "pattern": "go.mod"
                },
                "go.sum": {
                    "pattern": "go.sum"
                }
            },
            "java": {
                "pom.xml": {
                    "pattern": "pom.xml"
                }
            }
        }
        all_files = []
        for ecosystem in socket_globs:
            patterns = socket_globs[ecosystem]
            for file_name in patterns:
                pattern = patterns[file_name]["pattern"]
                file_path = f"{path}/**/{pattern}"
                files = glob(file_path, recursive=True)
                for file in files:
                    if "/" in file:
                        _, base_name = file.rsplit("/", 1)
                    else:
                        base_name = file
                    if new_files is not None and len(new_files) > 0 and base_name not in new_files:
                        continue
                    if platform.system() == "Windows":
                        file = file.replace("\\", "/")
                    found_path, file_name = file.rsplit("/", 1)
                    details = (found_path, file_name)
                    all_files.append(details)
        return all_files

    @staticmethod
    def create_full_scan(files: list, params: FullScanParams, workspace: str) -> FullScan:
        """
        Calls the full scan API to create a new Full Scan
        :param files: list - Globbed files of manifest files
        :param params: FullScanParams - Set of query params to pass to the endpoint
        :param workspace: str - Path of workspace
        :return:
        """
        send_files = []
        for path, name in files:
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
        full_uri = f"{full_scan_path}?{query_params}"
        response = do_request(full_uri, method="POST", files=send_files)
        results = response.json()
        full_scan = FullScan(**results)
        full_scan.sbom_artifacts = Core.get_sbom_data(full_scan.id)
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

    @staticmethod
    def get_head_scan_for_repo(repo_slug: str):
        """
        Get the head scan ID for a repository to use for the diff
        :param repo_slug: Str - Repo slug for the repository that is being diffed
        :return:
        """
        repo_path = f"{repository_path}/{repo_slug}"
        response = do_request(repo_path)
        results = response.json()
        repository = Repository(**results)
        return repository.head_full_scan_id

    @staticmethod
    def get_full_scan(full_scan_id: str) -> FullScan:
        """
        Get the specified full scan and return a FullScan object
        :param full_scan_id: str - ID of the full scan to pull
        :return:
        """
        full_scan_url = f"{full_scan_path}/{full_scan_id}"
        response = do_request(full_scan_url)
        results = response.json()
        full_scan = FullScan(**results)
        full_scan.sbom_artifacts = Core.get_sbom_data(full_scan.id)
        return full_scan

    @staticmethod
    def create_new_diff(path: str, params: FullScanParams, workspace: str, new_files: list = None) -> Diff:
        """
        1. Get the head full scan. If it isn't present because this repo doesn't exist yet return an Empty full scan.
        2. Create a new Full scan for the current run
        3. Compare the head and new Full scan
        4. Return a Diff report
        :param path: Str - path of where to look for manifest files for the new Full Scan
        :param params: FullScanParams - Query params for the Full Scan endpoint
        :param workspace: str - Path for workspace
        :param new_files:
        :return:
        """
        files = Core.find_files(path, new_files)
        try:
            head_full_scan_id = Core.get_head_scan_for_repo(params.repo)
            if head_full_scan_id is None or head_full_scan_id == "":
                head_full_scan = []
            else:
                head_start = time.time()
                head_full_scan = Core.get_sbom_data(head_full_scan_id)
                head_end = time.time()
                total_head_time = head_end - head_start
                log.info(f"Total time to get head full-scan {total_head_time: .2f}")
        except APIResourceNotFound:
            head_full_scan = []
        if files is not None and len(files) > 0:
            new_scan_start = time.time()
            new_full_scan = Core.create_full_scan(files, params, workspace)
            new_full_scan.packages = Core.create_sbom_dict(new_full_scan.sbom_artifacts)
            new_scan_end = time.time()
            total_new_time = new_scan_end - new_scan_start
            log.info(f"Total time to get new full-scan {total_new_time: .2f}")
            diff_report = Core.compare_sboms(new_full_scan.sbom_artifacts, head_full_scan)
            diff_report.packages = new_full_scan.packages
        else:
            diff_report = Diff()
        return diff_report

    @staticmethod
    def compare_sboms(new_scan: list, head_scan: list) -> Diff:
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

        for package_id in new_packages:
            purl, package = Core.create_purl(package_id, new_packages)
            if package_id not in head_packages and package.direct:
                diff.new_packages.append(purl)
            new_scan_alerts = Core.create_issue_alerts(package, new_scan_alerts, new_packages)
        for package_id in head_packages:
            purl, package = Core.create_purl(package_id, head_packages)
            if package_id not in new_packages and package.direct:
                diff.removed_packages.append(purl)
            head_scan_alerts = Core.create_issue_alerts(package, head_scan_alerts, head_packages)
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
            if alert["type"] in alert_types and new_alert:
                value = alert_types[alert["type"]]
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
        for alert_key in new_scan_alerts:
            if alert_key not in head_scan_alerts:
                new_alerts = new_scan_alerts[alert_key]
                for alert in new_alerts:
                    if Core.is_error(alert):
                        alerts.append(alert)
            else:
                new_alerts = new_scan_alerts[alert_key]
                head_alerts = head_scan_alerts[alert_key]
                for alert in new_alerts:
                    if alert not in head_alerts and Core.is_error(alert):
                        alerts.append(alert)
        return alerts

    @staticmethod
    def is_error(alert: Alert):
        """
        Compare the current alert against the Security Policy to determine if it should be included. Can be overridden
        with all_new_alerts Global setting if desired to return all alerts and not just the error category from the
        security policy.
        :param alert:
        :return:
        """
        if all_new_alerts or (alert.type in security_policy and security_policy[alert.type]['action'] == "error"):
            return True
        else:
            return False

    @staticmethod
    def create_issue_alerts(package: Package, alerts: dict, packages: dict) -> dict:
        """
        Create the Issue Alerts from the package and base alert data.
        :param package: Package - Current package that is being looked at for Alerts
        :param alerts: Dict - All found Issue Alerts across all packages
        :param packages: Dict - All packages detected in the SBOM and needed to find top level packages
        :return:
        """
        for item in package.alerts:
            alert = Alert(**item)
            try:
                props = getattr(all_issues, alert.type)
            except AttributeError:
                props = None
            if props is not None:
                description = props.description
                title = props.title
                suggestion = props.suggestion
                next_step_title = props.nextStepTitle
            else:
                description = ""
                title = ""
                suggestion = ""
                next_step_title = ""
            introduced_by = Core.get_source_data(package, packages)
            issue_alert = Issue(
                pkg_type=package.type,
                pkg_name=package.name,
                pkg_version=package.version,
                pkg_id=package.id,
                type=alert.type,
                severity=alert.severity,
                key=alert.key,
                props=alert.props,
                description=description,
                title=title,
                suggestion=suggestion,
                next_step_title=next_step_title,
                introduced_by=introduced_by,
                purl=package.purl,
                url=package.url
            )
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
