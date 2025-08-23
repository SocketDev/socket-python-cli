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
        """
        Determine the appropriate authentication headers for GitLab API.
        Uses the same logic as GitlabConfig._get_auth_headers()
        """
        return self._get_gitlab_auth_headers(self.token)
    
    @staticmethod
    def _get_gitlab_auth_headers(token: str) -> dict:
        """
        Determine the appropriate authentication headers for GitLab API.
        
        GitLab supports two authentication patterns:
        1. Bearer token (OAuth 2.0 tokens, personal access tokens with api scope)
        2. Private token (personal access tokens)
        """
        import os
        
        base_headers = {
            'User-Agent': 'SocketPythonScript/0.0.1',
            "accept": "application/json"
        }
        
        # Check if this is a GitLab CI job token
        if token == os.getenv('CI_JOB_TOKEN'):
            return {
                **base_headers,
                'Authorization': f"Bearer {token}"
            }
        
        # Check for personal access token pattern
        if token.startswith('glpat-'):
            return {
                **base_headers,
                'Authorization': f"Bearer {token}"
            }
        
        # Check for OAuth token pattern (typically longer and alphanumeric)
        if len(token) > 40 and token.isalnum():
            return {
                **base_headers,
                'Authorization': f"Bearer {token}"
            }
        
        # Default to PRIVATE-TOKEN for other token types
        return {
            **base_headers,
            'PRIVATE-TOKEN': f"{token}"
        }
