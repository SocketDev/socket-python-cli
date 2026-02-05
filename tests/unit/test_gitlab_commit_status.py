"""Tests for GitLab commit status integration"""
import os
import pytest
from unittest.mock import patch, MagicMock, call

from socketsecurity.core.scm.gitlab import Gitlab, GitlabConfig


def _make_gitlab_config(**overrides):
    defaults = dict(
        commit_sha="abc123def456",
        api_url="https://gitlab.example.com/api/v4",
        project_dir="/builds/test",
        mr_source_branch="feature",
        mr_iid="42",
        mr_project_id="99",
        commit_message="test commit",
        default_branch="main",
        project_name="test-project",
        pipeline_source="merge_request_event",
        commit_author="dev@example.com",
        token="glpat-test",
        repository="test-project",
        is_default_branch=False,
        headers={"Authorization": "Bearer glpat-test", "accept": "application/json"},
    )
    defaults.update(overrides)
    return GitlabConfig(**defaults)


class TestSetCommitStatus:
    """Test Gitlab.set_commit_status()"""

    @patch("socketsecurity.core.scm.gitlab.requests.post")
    def test_calls_correct_url_and_json_payload(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        config = _make_gitlab_config()
        gl = Gitlab(client=MagicMock(), config=config)

        gl.set_commit_status("success", "No blocking issues", "https://app.socket.dev/report/123")

        mock_post.assert_called_once_with(
            "https://gitlab.example.com/api/v4/projects/99/statuses/abc123def456",
            json={
                "state": "success",
                "context": "socket-security",
                "description": "No blocking issues",
                "ref": "feature",
                "target_url": "https://app.socket.dev/report/123",
            },
            headers=config.headers,
        )

    @patch("socketsecurity.core.scm.gitlab.requests.post")
    def test_failed_state_payload(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        config = _make_gitlab_config()
        gl = Gitlab(client=MagicMock(), config=config)

        gl.set_commit_status("failed", "3 blocking alert(s) found")

        payload = mock_post.call_args.kwargs["json"]
        assert payload["state"] == "failed"
        assert payload["description"] == "3 blocking alert(s) found"
        assert "target_url" not in payload

    @patch("socketsecurity.core.scm.gitlab.requests.post")
    def test_skipped_when_no_mr_project_id(self, mock_post):
        config = _make_gitlab_config(mr_project_id=None)
        gl = Gitlab(client=MagicMock(), config=config)

        gl.set_commit_status("success", "No blocking issues")

        mock_post.assert_not_called()

    @patch("socketsecurity.core.scm.gitlab.requests.post")
    def test_graceful_error_handling(self, mock_post):
        mock_post.side_effect = Exception("connection error")
        config = _make_gitlab_config()
        gl = Gitlab(client=MagicMock(), config=config)

        # Should not raise
        gl.set_commit_status("success", "No blocking issues")

    @patch("socketsecurity.core.scm.gitlab.requests.post")
    def test_no_target_url_omitted_from_payload(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        config = _make_gitlab_config()
        gl = Gitlab(client=MagicMock(), config=config)

        gl.set_commit_status("success", "No blocking issues", target_url="")

        payload = mock_post.call_args.kwargs["json"]
        assert "target_url" not in payload

    @patch("socketsecurity.core.scm.gitlab.requests.post")
    def test_auth_fallback_on_401(self, mock_post):
        resp_401 = MagicMock(status_code=401)
        resp_401.raise_for_status.side_effect = Exception("401")
        resp_200 = MagicMock(status_code=200)
        mock_post.side_effect = [resp_401, resp_200]

        config = _make_gitlab_config()
        gl = Gitlab(client=MagicMock(), config=config)

        gl.set_commit_status("success", "No blocking issues")

        assert mock_post.call_count == 2
        # Second call should use fallback headers (PRIVATE-TOKEN)
        fallback_headers = mock_post.call_args_list[1].kwargs["headers"]
        assert "PRIVATE-TOKEN" in fallback_headers


class TestEnableCommitStatusCliArg:
    """Test --enable-commit-status CLI argument parsing"""

    def test_default_is_false(self):
        from socketsecurity.config import create_argument_parser
        parser = create_argument_parser()
        args = parser.parse_args([])
        assert args.enable_commit_status is False

    def test_flag_sets_true(self):
        from socketsecurity.config import create_argument_parser
        parser = create_argument_parser()
        args = parser.parse_args(["--enable-commit-status"])
        assert args.enable_commit_status is True

    def test_underscore_alias(self):
        from socketsecurity.config import create_argument_parser
        parser = create_argument_parser()
        args = parser.parse_args(["--enable_commit_status"])
        assert args.enable_commit_status is True
