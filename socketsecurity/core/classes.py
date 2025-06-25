import json
from dataclasses import dataclass, field
from typing import Dict, List, TypedDict, Any, Optional

from socketdev.fullscans import FullScanMetadata, SocketArtifact, SocketArtifactLink, DiffType, SocketManifestReference, SocketScore, SocketAlert

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
    """Represents a Socket Security scan report for a repository."""
    
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
    """
    Represents Socket Security scores for a package or repository.
    
    All scores are normalized to 0-100 range, converting from 0-1 if needed.
    """
    
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
        """
        Convert Score object to dictionary with default values.
        
        Returns:
            Dictionary containing all score values, defaulting to 0 if not set
        """
        return {
            "supplyChain": self.supplyChain if hasattr(self, "supplyChain") else 0,
            "quality": self.quality if hasattr(self, "quality") else 0,
            "maintenance": self.maintenance if hasattr(self, "maintenance") else 0,
            "license": self.license if hasattr(self, "license") else 0,
            "overall": self.overall if hasattr(self, "overall") else 0,
            "vulnerability": self.vulnerability if hasattr(self, "vulnerability") else 0
        }

class AlertCounts(TypedDict):
    """Type definition for counting alerts by severity level."""
    critical: int
    high: int
    middle: int
    low: int

@dataclass(kw_only=True)
class Package():
    """
    Represents a package detected in a Socket Security scan.
    
    Inherits from SocketArtifactLink to maintain connection to dependency tree.
    Adds additional fields for package-specific information.
    """
    
    # Common properties from both artifact types
    type: str
    name: str
    version: str
    release: str
    diffType: str
    id: str
    author: List[str] = field(default_factory=list)
    score: SocketScore
    alerts: List[SocketAlert]
    size: Optional[int] = None
    license: Optional[str] = None
    namespace: Optional[str] = None
    topLevelAncestors: Optional[List[str]] = None
    direct: Optional[bool] = False
    manifestFiles: Optional[List[SocketManifestReference]] = None
    dependencies: Optional[List[str]] = None
    artifact: Optional[SocketArtifactLink] = None
    
    # Package-specific fields
    license_text: str = ""
    purl: str = ""
    transitives: int = 0
    url: str = ""

    # Artifact-specific fields
    licenseDetails: Optional[list] = None
    licenseAttrib: Optional[List] = None


    @classmethod
    def from_socket_artifact(cls, data: dict) -> "Package":
        """
        Create a Package from a SocketArtifact dictionary.
        
        Args:
            data: Dictionary containing SocketArtifact data
            
        Returns:
            New Package instance
        """
        purl = f"{data['type']}/"
        namespace = data.get("namespace")
        if namespace:
            purl += f"{namespace}@"
        purl += f"{data['name']}@{data['version']}"
        base_url = "https://socket.dev"
        url = f"{base_url}/{data['type']}/package/{namespace or ''}{data['name']}/overview/{data['version']}"
        return cls(
            id=data["id"],
            name=data["name"],
            version=data["version"],
            type=data["type"],
            score=data["score"],
            alerts=data["alerts"],
            author=data.get("author", []),
            size=data.get("size"),
            license=data.get("license"),
            topLevelAncestors=data["topLevelAncestors"],
            direct=data.get("direct", False),
            manifestFiles=data.get("manifestFiles", []),
            dependencies=data.get("dependencies"),
            artifact=data.get("artifact"),
            purl=purl,
            url=url,
            namespace=namespace
        )

    @classmethod
    def from_diff_artifact(cls, data: dict) -> "Package":
        """
        Create a Package from a DiffArtifact dictionary.
        
        Args:
            data: Dictionary containing DiffArtifact data
            
        Returns:
            New Package instance
            
        Raises:
            ValueError: If reference data cannot be found in DiffArtifact
        """
        ref = None
        if data["diffType"] in ["added", "updated", "unchanged"] and data.get("head"):
            ref = data["head"][0]
        elif data["diffType"] in ["removed", "replaced"] and data.get("base"):
            ref = data["base"][0]

        if not ref:
            raise ValueError("Could not find reference data in DiffArtifact")

        return cls(
            id=data["id"],
            name=data["name"],
            version=data["version"],
            type=data["type"],
            score=data["score"],
            alerts=data["alerts"],
            author=data.get("author", []),
            size=data.get("size"),
            license=data.get("license"),
            topLevelAncestors=ref["topLevelAncestors"],
            direct=ref.get("direct", False),
            manifestFiles=ref.get("manifestFiles", []),
            dependencies=ref.get("dependencies"),
            artifact=ref.get("artifact"),
            namespace=data.get('namespace', None),
            release=ref.get("release", None),
            diffType=ref.get("diffType", None),
        )

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
    """
    Represents a YAML configuration file with associated alerts.
    
    Stores metadata about the file and any security alerts found during scanning.
    """
    
    path: str
    name: str
    team: list
    module: list
    production: bool
    pii: bool
    alerts: dict
    error_ids: list

    def __init__(self, **kwargs):
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
    """Represents a security alert with its type, severity, and associated properties."""
    
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
    """
    Represents a complete Socket Security scan of a repository.
    
    Inherits from FullScanMetadata and adds fields for SBOM artifacts and package data.
    """
    
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
    """Represents a source code repository with its metadata and scan results."""
    
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
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)

    def __str__(self):
        return json.dumps(self.__dict__)

class Purl:
    """
    Represents a Package URL (PURL) with extended metadata.
    
    Includes package identification, authorship, and dependency information.
    """
    
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
    scores: dict[str, int]

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
        Creates markdown-formatted links to author profiles.
        
        Args:
            authors: List of author names
            ecosystem: Package ecosystem (npm, pypi, etc.)
            
        Returns:
            Comma-separated string of markdown links to author profiles
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
        """
        Convert Purl object to a dictionary representation.
        
        Returns:
            Dictionary containing all Purl attributes
        """
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
    """
    Represents differences between two Socket Security scans.
    
    Tracks changes in packages, capabilities, and security alerts between scans.
    """
    
    new_packages: list[Purl]
    removed_packages: list[Purl]
    packages: dict[str, Package]
    new_capabilities: Dict[str, List[str]]
    new_alerts: list[Issue]
    id: str
    sbom: str
    report_url: str
    diff_url: str
    new_scan_id: str

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
        """
        Convert Diff object to a dictionary representation.
        
        Returns:
            Dictionary containing all Diff attributes with nested objects converted
        """
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

class Comment:
    """Represents a GitHub comment with its metadata and content."""
    
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

    def __str__(self):
        return json.dumps(self.__dict__)
