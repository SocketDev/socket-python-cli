import json


__all__ = [
    "Report",
    "Score",
    "Package",
    "Issue",
    "YamlFile",
    "Alert",
    "FullScan",
    "FullScanParams",
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


class Package:
    type: str
    name: str
    version: str
    release: str
    id: str
    direct: bool
    manifestFiles: list
    author: list
    size: int
    score: dict
    scores: Score
    alerts: list
    error_alerts: list
    alert_counts: dict
    topLevelAncestors: list
    url: str
    transitives: int
    license: str
    license_text: str
    purl: str

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
        if not hasattr(self, "direct"):
            self.direct = False
        else:
            if str(self.direct).lower() == "true":
                self.direct = True
        self.url = f"https://socket.dev/{self.type}/package/{self.name}/overview/{self.version}"
        if hasattr(self, 'score'):
            self.scores = Score(**self.score)
        if not hasattr(self, "alerts"):
            self.alerts = []
        if not hasattr(self, "topLevelAncestors"):
            self.topLevelAncestors = []
        if not hasattr(self, "manifestFiles"):
            self.manifestFiles = []
        if not hasattr(self, "transitives"):
            self.transitives = 0
        if not hasattr(self, "author"):
            self.author = []
        if not hasattr(self, "size"):
            self.size = 0
        self.alert_counts = {
            "critical": 0,
            "high": 0,
            "middle": 0,
            "low": 0
        }
        self.error_alerts = []
        if not hasattr(self, "license"):
            self.license = "NoLicenseFound"
        if not hasattr(self, "license_text"):
            self.license_text = ""
        self.url = f"https://socket.dev/{self.type}/package/{self.name}/overview/{self.version}"
        self.purl = f"{self.type}/{self.name}@{self.version}"

    def __str__(self):
        return json.dumps(self.__dict__)


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
    is_error: bool
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
        if not hasattr(self, "introduced_by"):
            self.introduced_by = []
        if not hasattr(self, "manifests"):
            self.manifests = ""

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


class FullScan:
    id: str
    created_at: str
    updated_at: str
    organization_id: str
    repository_id: str
    branch: str
    commit_message: str
    commit_hash: str
    pull_request: int
    sbom_artifacts: list
    packages: dict

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
        if not hasattr(self, "sbom_artifacts"):
            self.sbom_artifacts = []

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
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)

    def __str__(self):
        return json.dumps(self.__dict__)


class FullScanParams:
    repo: str
    branch: str
    commit_message: str
    commit_hash: str
    pull_request: int
    committer: str
    make_default_branch: bool
    set_as_pending_head: bool

    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)

    def __str__(self):
        return json.dumps(self.__dict__)


class Diff:
    new_packages: list
    new_capabilities: dict
    removed_packages: list
    new_alerts: list
    id: str
    sbom: str
    packages: dict

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
    capabilities: dict
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
            self.capabilities = {}
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
