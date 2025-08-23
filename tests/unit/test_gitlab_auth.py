"""Tests for GitLab authentication patterns"""
import os
import pytest
from unittest.mock import patch, MagicMock

from socketsecurity.core.scm.gitlab import GitlabConfig


class TestGitlabAuthHeaders:
    """Test GitLab authentication header generation"""

    def test_ci_job_token_uses_bearer(self):
        """CI_JOB_TOKEN should always use Bearer authentication"""
        with patch.dict(os.environ, {'CI_JOB_TOKEN': 'ci-job-token-123'}):
            headers = GitlabConfig._get_auth_headers('ci-job-token-123')
            assert 'Authorization' in headers
            assert headers['Authorization'] == 'Bearer ci-job-token-123'
            assert 'PRIVATE-TOKEN' not in headers

    def test_personal_access_token_uses_bearer(self):
        """Personal access tokens (glpat-*) should use Bearer authentication"""
        token = 'glpat-xxxxxxxxxxxxxxxxxxxx'
        headers = GitlabConfig._get_auth_headers(token)
        assert 'Authorization' in headers
        assert headers['Authorization'] == f'Bearer {token}'
        assert 'PRIVATE-TOKEN' not in headers

    def test_oauth_token_uses_bearer(self):
        """Long alphanumeric tokens (OAuth) should use Bearer authentication"""
        token = 'a' * 50  # 50 character alphanumeric token
        headers = GitlabConfig._get_auth_headers(token)
        assert 'Authorization' in headers
        assert headers['Authorization'] == f'Bearer {token}'
        assert 'PRIVATE-TOKEN' not in headers

    def test_short_token_uses_private_token(self):
        """Short tokens should use PRIVATE-TOKEN authentication"""
        token = 'short-token-123'
        headers = GitlabConfig._get_auth_headers(token)
        assert 'PRIVATE-TOKEN' in headers
        assert headers['PRIVATE-TOKEN'] == token
        assert 'Authorization' not in headers

    def test_mixed_alphanumeric_token_uses_private_token(self):
        """Tokens with non-alphanumeric characters should use PRIVATE-TOKEN"""
        token = 'token-with-dashes-and_underscores'
        headers = GitlabConfig._get_auth_headers(token)
        assert 'PRIVATE-TOKEN' in headers
        assert headers['PRIVATE-TOKEN'] == token
        assert 'Authorization' not in headers

    def test_all_headers_include_base_headers(self):
        """All authentication patterns should include base headers"""
        test_tokens = [
            'glpat-xxxxxxxxxxxxxxxxxxxx',  # Bearer
            'short-token'  # PRIVATE-TOKEN
        ]
        
        for token in test_tokens:
            headers = GitlabConfig._get_auth_headers(token)
            assert headers['User-Agent'] == 'SocketPythonScript/0.0.1'
            assert headers['accept'] == 'application/json'

    @patch.dict(os.environ, {'CI_JOB_TOKEN': 'ci-token-123'})
    def test_ci_job_token_detection_priority(self):
        """CI_JOB_TOKEN should be detected even if token doesn't match CI_JOB_TOKEN value"""
        # This tests the case where GITLAB_TOKEN != CI_JOB_TOKEN
        headers = GitlabConfig._get_auth_headers('different-token')
        # Should not use Bearer since token doesn't match CI_JOB_TOKEN
        assert 'PRIVATE-TOKEN' in headers
        assert headers['PRIVATE-TOKEN'] == 'different-token'


class TestGitlabConfigFromEnv:
    """Test GitlabConfig.from_env() method"""

    @patch.dict(os.environ, {
        'GITLAB_TOKEN': 'glpat-test-token',
        'CI_PROJECT_NAME': 'test-project',
        'CI_API_V4_URL': 'https://gitlab.example.com/api/v4',
        'CI_COMMIT_SHA': 'abc123',
        'CI_PROJECT_DIR': '/builds/test',
        'CI_PIPELINE_SOURCE': 'merge_request_event'
    })
    def test_from_env_creates_config_with_correct_headers(self):
        """from_env should create config with appropriate auth headers"""
        config = GitlabConfig.from_env()
        
        # Should use Bearer for glpat- token
        assert 'Authorization' in config.headers
        assert config.headers['Authorization'] == 'Bearer glpat-test-token'
        assert 'PRIVATE-TOKEN' not in config.headers
        assert config.token == 'glpat-test-token'

    @patch.dict(os.environ, {
        'GITLAB_TOKEN': 'custom-token',
        'CI_PROJECT_NAME': 'test-project'
    }, clear=True)
    def test_from_env_with_private_token(self):
        """from_env should use PRIVATE-TOKEN for non-standard tokens"""
        config = GitlabConfig.from_env()
        
        # Should use PRIVATE-TOKEN for custom token
        assert 'PRIVATE-TOKEN' in config.headers
        assert config.headers['PRIVATE-TOKEN'] == 'custom-token'
        assert 'Authorization' not in config.headers

    def test_from_env_missing_token_exits(self):
        """from_env should exit when GITLAB_TOKEN is missing"""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit):
                GitlabConfig.from_env()


if __name__ == '__main__':
    pytest.main([__file__])
