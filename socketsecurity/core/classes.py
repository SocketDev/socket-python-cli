import json
from dataclasses import dataclass, field
from typing import Dict, List, TypedDict, Any

from socketdev.fullscans import FullScanMetadata, SocketArtifact

__all__ = [
    "Report",
    "Score",
    "Package",
    "Issue",
    "YamlFile",
    "Alert",
    "FullScan",
    "Repository",
    "Diff",
    "Purl",
    "Comment"
]


class Report:
    branch: str
    commit: str
    id: str
    pull_requests: list
    url: str
    repo: str
    processed: bool
    owner: str
    created_at: str
    sbom: list

    def __init__(self, **kwargs):
        self.sbom = []
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
        if not hasattr(self, "processed"):
            self.processed = False
        if hasattr(self, "pull_requests"):
            if self.pull_requests is not None:
                self.pull_requests = json.loads(str(self.pull_requests))

    def __str__(self):
        return json.dumps(self.__dict__)

class Score:
    supplyChain: float
    quality: float
    maintenance: float
    license: float
    overall: float
    vulnerability: float

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
        for score_name in self.__dict__:
            score = getattr(self, score_name)
            if score <= 1:
                score = score * 100
                setattr(self, score_name, score)

    def __str__(self):
        return json.dumps(self.__dict__)

    def to_dict(self) -> dict:
        return {
            "supplyChain": self.supplyChain if hasattr(self, "supplyChain") else 0,
            "quality": self.quality if hasattr(self, "quality") else 0,
            "maintenance": self.maintenance if hasattr(self, "maintenance") else 0,
            "license": self.license if hasattr(self, "license") else 0,
            "overall": self.overall if hasattr(self, "overall") else 0,
            "vulnerability": self.vulnerability if hasattr(self, "vulnerability") else 0
        }

class AlertCounts(TypedDict):
    critical: int
    high: int
    middle: int
    low: int

@dataclass(kw_only=True)
class Package(SocketArtifact):
    alert_counts: AlertCounts = field(default_factory=lambda: AlertCounts(
        critical=0,
        high=0,
        middle=0,
        low=0
    ))
    error_alerts: list = field(default_factory=list)
    license_text: str = ""
    purl: str = ""
    transitives: int = 0
    url: str = ""

    def __post_init__(self):
        # Convert string "true"/"false" to boolean for direct
        if isinstance(self.direct, str):
            self.direct = self.direct.lower() == "true"
        
        # Set computed values
        self.url = f"https://socket.dev/{self.type}/package/{self.name}/overview/{self.version}"
        self.purl = f"pkg:{self.type}/{self.name}@{self.version}"

    def __str__(self):
        return json.dumps(self.__dict__)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "name": self.name,
            "version": self.version,
            "release": self.release if hasattr(self, "release") else None,
            "id": self.id,
            "direct": self.direct,
            "manifestFiles": self.manifestFiles,
            "author": self.author,
            "size": self.size,
            "score": self.score if hasattr(self, "score") else {},
            "alerts": self.alerts,
            "error_alerts": self.error_alerts,
            "alert_counts": self.alert_counts,
            "topLevelAncestors": self.topLevelAncestors,
            "url": self.url,
            "transitives": self.transitives,
            "license": self.license,
            "license_text": self.license_text,
            "purl": self.purl
        }

class Issue:
    pkg_type: str
    pkg_name: str
    pkg_version: str
    category: str
    type: str
    severity: str
    pkg_id: str
    props: dict
    key: str
    error: bool
    warn: bool
    ignore: bool
    monitor: bool
    description: str
    title: str
    emoji: str
    next_step_title: str
    suggestion: str
    introduced_by: list
    manifests: str
    url: str
    purl: str

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)

        if hasattr(self, "created_at"):
            self.created_at = self.created_at.strip(" (Coordinated Universal Time)")
        if not hasattr(self, "manifests"):
            self.manifests = ""
        if not hasattr(self, "suggestion"):
            self.suggestion = ""
        if not hasattr(self, "introduced_by"):
            self.introduced_by = []
        else:
            for item in self.introduced_by:
                pkg, manifest = item
                self.manifests += f"{manifest};"
            self.manifests = self.manifests.rstrip(";")
        if not hasattr(self, "error"):
            self.error = False
        if not hasattr(self, "warn"):
            self.warn = False
        if not hasattr(self, "monitor"):
            self.monitor = False
        if not hasattr(self, "ignore"):
            self.ignore = False

    def __str__(self):
        return json.dumps(self.__dict__)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return self.__dict__ != other.__dict__


class YamlFile:
    path: str
    name: str
    team: list
    module: list
    production: bool
    pii: bool
    alerts: dict
    error_ids: list

    def __init__(
            self,
            **kwargs
    ):
        self.alerts = {}
        self.error_ids = []

        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)

    def __str__(self):
        alerts = {}
        for issue_key in self.alerts:
            issue: Issue
            issue = self.alerts[issue_key]["issue"]
            manifests = self.alerts[issue_key]["manifests"]
            new_alert = {
                "issue": json.loads(str(issue)),
                "manifests": manifests
            }
            alerts[issue_key] = new_alert

        dump_object = self
        dump_object.alerts = alerts
        return json.dumps(dump_object.__dict__)

class Alert:
    key: str
    type: str
    severity: str
    category: str
    props: dict

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
        if not hasattr(self, "props"):
            self.props = {}

    def __str__(self):
        return json.dumps(self.__dict__)


class FullScan(FullScanMetadata):
    sbom_artifacts: list[SocketArtifact]
    packages: dict[str, Package]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not hasattr(self, "sbom_artifacts"):
            self.sbom_artifacts = []
        if not hasattr(self, "packages"):
            self.packages = {}

    def __str__(self):
        return json.dumps(self.__dict__)


class Repository:
    id: str
    created_at: str
    updated_at: str
    head_full_scan_id: str
    name: str
    description: str
    homepage: str
    visibility: str
    archived: bool
    default_branch: str

    def __init__(self, **kwargs):
        print(f"Repository.__init__ called with kwargs: {kwargs}")  # Debug
        if kwargs:
            for key, value in kwargs.items():
                print(f"Setting {key}={value}")  # Debug
                setattr(self, key, value)
        print(f"Final Repository object dict: {self.__dict__}")  # Debug

    def __str__(self):
        return json.dumps(self.__dict__)



class Purl:
    id: str
    name: str
    version: str
    ecosystem: str
    direct: bool
    author: list
    size: int
    transitives: int
    introduced_by: list
    capabilities: List[str]
    is_new: bool
    author_url: str
    url: str
    purl: str

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
        if not hasattr(self, "introduced_by"):
            self.new_packages = []
        if not hasattr(self, "capabilities"):
            self.capabilities = []
        if not hasattr(self, "is_new"):
            self.is_new = False
        self.author_url = Purl.generate_author_data(self.author, self.ecosystem)

    @staticmethod
    def generate_author_data(authors: list, ecosystem: str) -> str:
        """
        Creates the Author links for the package
        :param authors:
        :param ecosystem:
        :return:
        """
        authors_str = ""
        for author in authors:
            author_url = f"https://socket.dev/{ecosystem}/user/{author}"
            authors_str += f"[{author}]({author_url}),"
        authors_str = authors_str.rstrip(",")
        return authors_str

    def __str__(self):
        return json.dumps(self.__dict__)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "direct": self.direct,
            "author": self.author,
            "size": self.size,
            "transitives": self.transitives,
            "introduced_by": self.introduced_by,
            "capabilities": self.capabilities,
            "is_new": self.is_new,
            "author_url": self.author_url,
            "url": self.url,
            "purl": self.purl
        }


class Diff:
    new_packages: list[Purl]
    new_capabilities: Dict[str, List[str]]
    removed_packages: list[Purl]
    new_alerts: list[Issue]
    id: str
    sbom: str
    packages: dict[str, Package]
    report_url: str
    diff_url: str

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
        if not hasattr(self, "new_packages"):
            self.new_packages = []
        if not hasattr(self, "removed_packages"):
            self.removed_packages = []
        if not hasattr(self, "new_alerts"):
            self.new_alerts = []
        if not hasattr(self, "new_capabilities"):
            self.new_capabilities = {}

    def __str__(self):
        return json.dumps(self.__dict__)

    def to_dict(self) -> dict:
        return {
            "new_packages": [p.to_dict() for p in self.new_packages],
            "new_capabilities": self.new_capabilities,
            "removed_packages": [p.to_dict() for p in self.removed_packages],
            "new_alerts": [alert.__dict__ for alert in self.new_alerts],
            "id": self.id,
            "sbom": self.sbom if hasattr(self, "sbom") else [],
            "packages": {k: v.to_dict() for k, v in self.packages.items()} if hasattr(self, "packages") else {},
            "report_url": self.report_url if hasattr(self, "report_url") else None,
            "diff_url": self.diff_url if hasattr(self, "diff_url") else None
        }


class GithubComment:
    url: str
    html_url: str
    issue_url: str
    id: int
    node_id: str
    user: dict
    created_at: str
    updated_at: str
    author_association: str
    body: str
    body_list: list
    reactions: dict
    performed_via_github_app: dict

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
        if not hasattr(self, "body_list"):
            self.body_list = []

    def __str__(self):
        return json.dumps(self.__dict__)


class GitlabComment:
    id: int
    type: str
    body: str
    attachment: str
    author: dict
    created_at: str
    updated_at: str
    system: bool
    notable_id: int
    noteable_type: str
    project_id: int
    resolvable: bool
    confidential: bool
    internal: bool
    imported: bool
    imported_from: str
    noteable_iid: int
    commands_changes: dict
    body_list: list

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
        if not hasattr(self, "body_list"):
            self.body_list = []

    def __str__(self):
        return json.dumps(self.__dict__)

class Comment:
    id: int
    body: str
    body_list: list

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
        if not hasattr(self, "body_list"):
            self.body_list = []

    def __str__(self):
        return json.dumps(self.__dict__)
