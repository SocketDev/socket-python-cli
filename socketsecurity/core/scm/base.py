from abc import ABC, abstractmethod
from typing import Dict

from ..classes import Comment
from .client import ScmClient


class SCM(ABC):
    def __init__(self, client: ScmClient):
        self.client = client

    @abstractmethod
    def check_event_type(self) -> str:
        """Determine the type of event (push, pr, comment)"""
        pass

    @abstractmethod
    def add_socket_comments(
        self,
        security_comment: str,
        overview_comment: str,
        comments: Dict[str, Comment],
        new_security_comment: bool = True,
        new_overview_comment: bool = True
    ) -> None:
        """Add or update comments on PR"""
        pass

    @abstractmethod
    def get_comments_for_pr(self, repo: str, pr: str) -> Dict[str, Comment]:
        """Get existing comments for PR"""
        pass

    @abstractmethod
    def remove_comment_alerts(self, comments: Dict[str, Comment]) -> None:
        """Process and remove alerts from comments"""
        pass
