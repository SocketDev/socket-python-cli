from abc import abstractmethod
from typing import Dict

from ..cli_client import CliClient


class ScmClient(CliClient):
    def __init__(self, token: str, api_url: str):
        self.token = token
        self.api_url = api_url

    @abstractmethod
    def get_headers(self) -> Dict:
        """Each SCM implements its own auth headers"""
        pass

    def request(self, path: str, **kwargs):
        """Override base request to use SCM-specific headers and base_url"""
        headers = kwargs.pop('headers', None) or self.get_headers()
        return super().request(
            path=path,
            headers=headers,
            base_url=self.api_url,
            **kwargs
        )

class GithubClient(ScmClient):
    def get_headers(self) -> Dict:
        return {
            'Authorization': f"Bearer {self.token}",
            'User-Agent': 'SocketPythonScript/0.0.1',
            "accept": "application/json"
        }

class GitlabClient(ScmClient):
    def get_headers(self) -> Dict:
        return {
            'Authorization': f"Bearer {self.token}",
            'User-Agent': 'SocketPythonScript/0.0.1',
            "accept": "application/json"
        }
