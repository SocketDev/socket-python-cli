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

    def test_calls_correct_api_path(self):
        config = _make_gitlab_config()
        client = MagicMock()
        gl = Gitlab(client=client, config=config)
        gl._request_with_fallback = MagicMock()

        gl.set_commit_status("success", "No blocking issues", "https://app.socket.dev/report/123")

        gl._request_with_fallback.assert_called_once_with(
            path="projects/99/statuses/abc123def456",
            payload={
                "state": "success",
                "name": "socket-security",
                "description": "No blocking issues",
                "target_url": "https://app.socket.dev/report/123",
            },
            method="POST",
            headers=config.headers,
            base_url=config.api_url,
        )

    def test_failed_state_payload(self):
        config = _make_gitlab_config()
        client = MagicMock()
        gl = Gitlab(client=client, config=config)
        gl._request_with_fallback = MagicMock()

        gl.set_commit_status("failed", "3 blocking alert(s) found")

        args = gl._request_with_fallback.call_args
        assert args.kwargs["payload"]["state"] == "failed"
        assert args.kwargs["payload"]["description"] == "3 blocking alert(s) found"
        assert "target_url" not in args.kwargs["payload"]

    def test_skipped_when_no_mr_project_id(self):
        config = _make_gitlab_config(mr_project_id=None)
        client = MagicMock()
        gl = Gitlab(client=client, config=config)
        gl._request_with_fallback = MagicMock()

        gl.set_commit_status("success", "No blocking issues")

        gl._request_with_fallback.assert_not_called()

    def test_graceful_error_handling(self):
        config = _make_gitlab_config()
        client = MagicMock()
        gl = Gitlab(client=client, config=config)
        gl._request_with_fallback = MagicMock(side_effect=Exception("API error"))

        # Should not raise
        gl.set_commit_status("success", "No blocking issues")

    def test_no_target_url_omitted_from_payload(self):
        config = _make_gitlab_config()
        client = MagicMock()
        gl = Gitlab(client=client, config=config)
        gl._request_with_fallback = MagicMock()

        gl.set_commit_status("success", "No blocking issues", target_url="")

        payload = gl._request_with_fallback.call_args.kwargs["payload"]
        assert "target_url" not in payload


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
