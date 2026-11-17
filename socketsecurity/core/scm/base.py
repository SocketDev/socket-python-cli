from abc import ABC, abstractmethod

from socketsecurity.core.classes import Comment

from .client import ScmClient


class SCM(ABC):
    def __init__(self, client: ScmClient):
        self.client = client

    @abstractmethod
    def check_event_type(self) -> str:
        """Determine the type of event (push, pr, comment)"""

    @abstractmethod
    def add_socket_comments(
        self,
        security_comment: str,
        overview_comment: str,
        comments: dict[str, Comment],
        new_security_comment: bool = True,
        new_overview_comment: bool = True,
    ) -> None:
        """Add or update comments on PR"""

    @abstractmethod
    def get_comments_for_pr(self, repo: str, pr: str) -> dict[str, Comment]:
        """Get existing comments for PR"""

    @abstractmethod
    def remove_comment_alerts(self, comments: dict[str, Comment]) -> None:
        """Process and remove alerts from comments"""
