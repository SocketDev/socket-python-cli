"""Integration test demonstrating GitLab authentication fallback"""
import os
from unittest.mock import patch, MagicMock
import pytest

from socketsecurity.core.scm.gitlab import Gitlab, GitlabConfig
from socketsecurity.socketcli import CliClient


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
        
        # First call (with PRIVATE-TOKEN) fails with 401
        auth_error = Exception()
        auth_error.response = MagicMock()
        auth_error.response.status_code = 401
        
        # Second call (with Bearer) succeeds
        success_response = {'notes': []}
        
        mock_client.request.side_effect = [auth_error, success_response]
        
        # Create GitLab instance with mock client
        gitlab = Gitlab(client=mock_client)
        
        # This should trigger the fallback mechanism
        result = gitlab.get_comments_for_pr()
        
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
        
        # First call (with Bearer) fails with 401
        auth_error = Exception()
        auth_error.response = MagicMock()
        auth_error.response.status_code = 401
        
        # Second call (with PRIVATE-TOKEN) succeeds
        success_response = {'notes': []}
        
        mock_client.request.side_effect = [auth_error, success_response]
        
        # Create GitLab instance with mock client
        gitlab = Gitlab(client=mock_client)
        
        # This should trigger the fallback mechanism
        result = gitlab.get_comments_for_pr()
        
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
        
        # Simulate a 500 error (not auth-related)
        server_error = Exception()
        server_error.response = MagicMock()
        server_error.response.status_code = 500
        
        mock_client.request.side_effect = server_error
        
        # Create GitLab instance with mock client
        gitlab = Gitlab(client=mock_client)
        
        # This should NOT trigger the fallback mechanism
        with pytest.raises(Exception):
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
        mock_client.request.return_value = {'notes': []}
        
        # Create GitLab instance with mock client
        gitlab = Gitlab(client=mock_client)
        
        # This should succeed on first try
        result = gitlab.get_comments_for_pr()
        
        # Verify only one request was made
        assert mock_client.request.call_count == 1


if __name__ == '__main__':
    pytest.main([__file__])
