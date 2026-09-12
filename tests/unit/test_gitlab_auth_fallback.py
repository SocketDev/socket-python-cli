"""GitLab authentication fallback.

_get_auth_headers guesses between Bearer and PRIVATE-TOKEN from the shape of the
token. When the guess is wrong the first request comes back 401, and the CLI
retries once under the other scheme rather than failing the run.

The retry hinges on which exception type it catches: CliClient translates every
requests error into APIFailure, which is not an HTTPError, so these tests drive
the failure the way CliClient actually raises it.
"""
import os
from unittest.mock import MagicMock, patch

import pytest
from socketdev.exceptions import APIFailure

from socketsecurity.core.scm.gitlab import Gitlab
from socketsecurity.socketcli import CliClient


def _auth_failure() -> APIFailure:
    """The exception CliClient raises for a 401, with the status preserved."""
    return APIFailure("Request failed: 401 Client Error", status_code=401)


class TestGitlabAuthFallback:
    """Test GitLab authentication fallback mechanism"""

    @patch.dict(os.environ, {
        'GITLAB_TOKEN': 'test-token',
        'CI_PROJECT_NAME': 'test-project',
        'CI_API_V4_URL': 'https://gitlab.example.com/api/v4',
        'CI_MERGE_REQUEST_IID': '123',
        'CI_MERGE_REQUEST_PROJECT_ID': '456'
    })
    def test_fallback_from_private_token_to_bearer(self):
        """Test fallback from PRIVATE-TOKEN to Bearer authentication"""
        # Create a mock client that simulates auth failure then success
        mock_client = MagicMock(spec=CliClient)
        
        # First call (with PRIVATE-TOKEN) fails with 401, second (Bearer) succeeds
        mock_client.request.side_effect = [_auth_failure(), MagicMock(json=lambda: [])]
        
        # Create GitLab instance with mock client
        gitlab = Gitlab(client=mock_client)
        
        # This should trigger the fallback mechanism
        gitlab.get_comments_for_pr()
        
        # Verify two requests were made
        assert mock_client.request.call_count == 2
        
        # First call should use PRIVATE-TOKEN (default for 'test-token')
        first_call_headers = mock_client.request.call_args_list[0][1]['headers']
        assert 'PRIVATE-TOKEN' in first_call_headers
        assert first_call_headers['PRIVATE-TOKEN'] == 'test-token'
        
        # Second call should use Bearer (fallback)
        second_call_headers = mock_client.request.call_args_list[1][1]['headers']
        assert 'Authorization' in second_call_headers
        assert second_call_headers['Authorization'] == 'Bearer test-token'

    @patch.dict(os.environ, {
        'GITLAB_TOKEN': 'glpat-test-token',
        'CI_PROJECT_NAME': 'test-project',
        'CI_API_V4_URL': 'https://gitlab.example.com/api/v4',
        'CI_MERGE_REQUEST_IID': '123',
        'CI_MERGE_REQUEST_PROJECT_ID': '456'
    })
    def test_fallback_from_bearer_to_private_token(self):
        """Test fallback from Bearer to PRIVATE-TOKEN authentication"""
        # Create a mock client that simulates auth failure then success
        mock_client = MagicMock(spec=CliClient)
        
        # First call (with Bearer) fails with 401, second (PRIVATE-TOKEN) succeeds
        mock_client.request.side_effect = [_auth_failure(), MagicMock(json=lambda: [])]
        
        # Create GitLab instance with mock client
        gitlab = Gitlab(client=mock_client)
        
        # This should trigger the fallback mechanism
        gitlab.get_comments_for_pr()
        
        # Verify two requests were made
        assert mock_client.request.call_count == 2
        
        # First call should use Bearer (default for 'glpat-' token)
        first_call_headers = mock_client.request.call_args_list[0][1]['headers']
        assert 'Authorization' in first_call_headers
        assert first_call_headers['Authorization'] == 'Bearer glpat-test-token'
        
        # Second call should use PRIVATE-TOKEN (fallback)
        second_call_headers = mock_client.request.call_args_list[1][1]['headers']
        assert 'PRIVATE-TOKEN' in second_call_headers
        assert second_call_headers['PRIVATE-TOKEN'] == 'glpat-test-token'

    @patch.dict(os.environ, {
        'GITLAB_TOKEN': 'test-token',
        'CI_PROJECT_NAME': 'test-project',
        'CI_API_V4_URL': 'https://gitlab.example.com/api/v4',
        'CI_MERGE_REQUEST_IID': '123',
        'CI_MERGE_REQUEST_PROJECT_ID': '456'
    })
    def test_non_auth_error_not_retried(self):
        """Test that non-authentication errors are not retried"""
        # Create a mock client that simulates a non-auth error
        mock_client = MagicMock(spec=CliClient)
        
        # A 500 is not recoverable by changing the auth scheme.
        mock_client.request.side_effect = APIFailure(
            "Request failed: 500 Server Error", status_code=500
        )
        
        # Create GitLab instance with mock client
        gitlab = Gitlab(client=mock_client)
        
        # This should NOT trigger the fallback mechanism
        with pytest.raises(APIFailure):
            gitlab.get_comments_for_pr()
        
        # Verify only one request was made (no retry)
        assert mock_client.request.call_count == 1

    @patch.dict(os.environ, {
        'GITLAB_TOKEN': 'test-token',
        'CI_PROJECT_NAME': 'test-project',
        'CI_API_V4_URL': 'https://gitlab.example.com/api/v4',
        'CI_MERGE_REQUEST_IID': '123',
        'CI_MERGE_REQUEST_PROJECT_ID': '456'
    })
    def test_successful_first_attempt_no_fallback(self):
        """Test that successful requests don't trigger fallback"""
        # Create a mock client that succeeds on first try
        mock_client = MagicMock(spec=CliClient)
        mock_client.request.return_value = MagicMock(json=lambda: [])
        
        # Create GitLab instance with mock client
        gitlab = Gitlab(client=mock_client)
        
        # This should succeed on first try
        gitlab.get_comments_for_pr()
        
        # Verify only one request was made
        assert mock_client.request.call_count == 1


if __name__ == '__main__':
    pytest.main([__file__])
