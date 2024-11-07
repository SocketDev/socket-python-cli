from dataclasses import dataclass
from typing import ClassVar

@dataclass
class CoreConfig:
    """Configuration for the Socket Security Core class"""

    # Required
    token: str

    # Optional with defaults
    api_url: str = "https://api.socket.dev/v0"
    timeout: int = 30
    enable_all_alerts: bool = False
    allow_unverified_ssl: bool = False

    # Constants
    SOCKET_DATE_FORMAT: ClassVar[str] = "%Y-%m-%dT%H:%M:%S.%fZ"
    DEFAULT_API_URL: ClassVar[str] = "https://api.socket.dev/v0"
    DEFAULT_TIMEOUT: ClassVar[int] = 30

    def __post_init__(self) -> None:
        """Validate and process config after initialization"""
        # Business rule validations
        if not self.token:
            raise ValueError("Token is required")
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")

        # Business logic
        if not self.token.endswith(':'):
            self.token = f"{self.token}:"
