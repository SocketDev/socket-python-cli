from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse
from typing import Set, List
import os

from socketdev.core.issues import AllIssues
from socketsecurity import __version__


default_exclude_dirs = {
    "node_modules", "bower_components", "jspm_packages",   # JS/TS
    "__pycache__", ".venv", "venv", "build", "dist",       # Python
    ".tox", ".mypy_cache", ".pytest_cache", "*.egg-info",
    "vendor"
}

@dataclass
class SocketConfig:
    api_key: str
    api_url: str = os.getenv("BASE_API_URL", "https://api.socket.dev/v0")
    timeout: int = 1200
    allow_unverified_ssl: bool = False
    org_id: Optional[str] = None
    org_slug: Optional[str] = None
    full_scan_path: Optional[str] = None
    repository_path: Optional[str] = None
    security_policy: Dict = None
    repo_visibility: Optional[str] = 'private'
    all_issues: Optional['AllIssues'] = None
    excluded_dirs: Set[str] = field(default_factory=lambda: default_exclude_dirs)
    excluded_ecosystems: List[str] = field(default_factory=lambda: [])
    version: str = __version__

    def __post_init__(self):
        """Validate configuration after initialization"""
        if not self.api_key:
            raise ValueError("API key is required")

        if self.timeout <= 0:
            raise ValueError("Timeout must be a positive integer")

        self._validate_api_url(self.api_url)

        # Initialize empty dict for security policy if None
        if self.security_policy is None:
            self.security_policy = {}

        # Initialize AllIssues if None
        if self.all_issues is None:
            self.all_issues = AllIssues()

    @staticmethod
    def _validate_api_url(url: str) -> None:
        """Validate that the API URL is a valid HTTPS URL"""
        try:
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError("Invalid URL format")
            if parsed.scheme != "https" and os.getenv("RUN_ENVIRONMENT", 'prod') != "dev":
                raise ValueError("API URL must use HTTPS")
        except Exception as e:
            raise ValueError(f"Invalid API URL: {str(e)}")

    def update_org_details(self, org_id: str, org_slug: str) -> None:
        """Update organization details and related paths"""
        self.org_id = org_id
        self.org_slug = org_slug
        base_path = f"orgs/{org_slug}"
        self.full_scan_path = f"{base_path}/full-scans"
        self.repository_path = f"{base_path}/repos"

    def update_security_policy(self, policy: Dict) -> None:
        """Update security policy"""
        self.security_policy = policy