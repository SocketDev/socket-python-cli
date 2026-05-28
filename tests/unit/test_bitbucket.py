"""Tests for Bitbucket SCM support."""
import base64
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from socketsecurity.core.scm.bitbucket import Bitbucket, BitbucketConfig


class TestBitbucketConfigFromEnv:
    @patch.dict(os.environ, {
        "BITBUCKET_TOKEN": "bbtoken-xyz",
        "BITBUCKET_REPO_FULL_NAME": "acme/widgets",
        "BITBUCKET_PR_ID": "42",
        "BITBUCKET_BRANCH": "feature/x",
        "BITBUCKET_PR_DESTINATION_BRANCH": "main",
        "BITBUCKET_COMMIT": "deadbeef",
    }, clear=True)
    def test_from_env_with_token_uses_bearer(self):
        config = BitbucketConfig.from_env()
        assert config.workspace == "acme"
        assert config.repo_slug == "widgets"
        assert config.pr_id == "42"
        assert config.source_branch == "feature/x"
        assert config.destination_branch == "main"
        assert config.commit_sha == "deadbeef"
        assert config.headers["Authorization"] == "Bearer bbtoken-xyz"
        assert config.headers["Content-Type"] == "application/json"
        assert config.api_url == "https://api.bitbucket.org/2.0"

    @patch.dict(os.environ, {
        "BITBUCKET_USERNAME": "alice",
        "BITBUCKET_APP_PASSWORD": "secret",
        "BITBUCKET_WORKSPACE": "acme",
        "BITBUCKET_REPO_SLUG": "widgets",
    }, clear=True)
    def test_from_env_falls_back_to_basic_auth(self):
        config = BitbucketConfig.from_env()
        expected = base64.b64encode(b"alice:secret").decode("ascii")
        assert config.headers["Authorization"] == f"Basic {expected}"

    @patch.dict(os.environ, {}, clear=True)
    def test_from_env_missing_credentials_exits(self):
        with pytest.raises(SystemExit):
            BitbucketConfig.from_env()

    @patch.dict(os.environ, {
        "BITBUCKET_TOKEN": "t",
        "BITBUCKET_REPO_FULL_NAME": "acme/widgets",
        "BITBUCKET_BRANCH": "main",
        "BITBUCKET_DEFAULT_BRANCH": "main",
    }, clear=True)
    def test_default_branch_detected(self):
        config = BitbucketConfig.from_env()
        assert config.is_default_branch is True

    @patch.dict(os.environ, {
        "BITBUCKET_TOKEN": "t",
        "BITBUCKET_REPO_FULL_NAME": "acme/widgets",
    }, clear=True)
    def test_pr_number_override(self):
        config = BitbucketConfig.from_env(pr_number="99")
        assert config.pr_id == "99"


class TestBitbucketCommentNormalization:
    def test_normalize_comment_extracts_raw_content(self):
        raw = {
            "id": 1234,
            "content": {"raw": "hello world", "markup": "markdown"},
            "user": {"display_name": "Alice", "nickname": "alice", "uuid": "{u-1}"},
            "created_on": "2024-01-01T00:00:00Z",
            "updated_on": "2024-01-02T00:00:00Z",
            "links": {"html": {"href": "https://example.com/c/1"}},
        }
        normalized = Bitbucket._normalize_comment(raw)
        assert normalized["id"] == 1234
        assert normalized["body"] == "hello world"
        assert normalized["user"]["login"] == "alice"
        assert normalized["html_url"] == "https://example.com/c/1"

    def test_normalize_skips_deleted(self):
        assert Bitbucket._normalize_comment({"id": 1, "deleted": True}) is None

    def test_normalize_handles_missing_content(self):
        normalized = Bitbucket._normalize_comment({"id": 7})
        assert normalized["body"] == ""
        assert normalized["id"] == 7


class TestBitbucketEventDetection:
    def _make(self, **overrides):
        cfg = BitbucketConfig(
            api_url="https://api.bitbucket.org/2.0",
            workspace="acme",
            repo_slug="widgets",
            repository="widgets",
            pr_id=overrides.get("pr_id"),
            source_branch="feature",
            destination_branch="main",
            default_branch="main",
            commit_sha="abc",
            is_default_branch=False,
            token="t",
            username=None,
            headers={},
        )
        return Bitbucket(client=MagicMock(), config=cfg)

    def test_check_event_type_diff_when_pr(self):
        scm = self._make(pr_id="5")
        assert scm.check_event_type() == "diff"

    def test_check_event_type_main_when_no_pr(self):
        scm = self._make(pr_id=None)
        assert scm.check_event_type() == "main"


class TestBitbucketCommentPosting:
    def _make_scm(self, pr_id="42"):
        cfg = BitbucketConfig(
            api_url="https://api.bitbucket.org/2.0",
            workspace="acme",
            repo_slug="widgets",
            repository="widgets",
            pr_id=pr_id,
            source_branch="feature",
            destination_branch="main",
            default_branch="main",
            commit_sha="abc",
            is_default_branch=False,
            token="t",
            username=None,
            headers={"Authorization": "Bearer t", "Content-Type": "application/json"},
        )
        client = MagicMock()
        return Bitbucket(client=client, config=cfg), client

    def test_post_comment_sends_json_content_raw(self):
        scm, client = self._make_scm()
        scm.post_comment("hello")
        call = client.request.call_args
        assert call.kwargs["method"] == "POST"
        assert call.kwargs["path"] == (
            "repositories/acme/widgets/pullrequests/42/comments"
        )
        assert call.kwargs["base_url"] == "https://api.bitbucket.org/2.0"
        assert json.loads(call.kwargs["payload"]) == {"content": {"raw": "hello"}}
        assert call.kwargs["headers"]["Content-Type"] == "application/json"

    def test_update_comment_uses_put_with_id(self):
        scm, client = self._make_scm()
        scm.update_comment("updated", "777")
        call = client.request.call_args
        assert call.kwargs["method"] == "PUT"
        assert call.kwargs["path"].endswith("/comments/777")
        assert json.loads(call.kwargs["payload"]) == {"content": {"raw": "updated"}}

    def test_add_socket_comments_creates_when_no_previous(self):
        scm, client = self._make_scm()
        scm.add_socket_comments(
            security_comment="security body",
            overview_comment="overview body",
            comments={},
            new_security_comment=True,
            new_overview_comment=True,
        )
        # Two POSTs (overview + security), no PUTs
        methods = [c.kwargs["method"] for c in client.request.call_args_list]
        assert methods.count("POST") == 2
        assert "PUT" not in methods

    def test_add_socket_comments_updates_existing(self):
        scm, client = self._make_scm()
        existing_overview = MagicMock(id=11)
        existing_security = MagicMock(id=22)
        scm.add_socket_comments(
            security_comment="security body",
            overview_comment="overview body",
            comments={"overview": existing_overview, "security": existing_security},
            new_security_comment=True,
            new_overview_comment=True,
        )
        methods = [c.kwargs["method"] for c in client.request.call_args_list]
        assert methods.count("PUT") == 2
        assert "POST" not in methods

    def test_add_socket_comments_no_pr_is_noop(self):
        scm, client = self._make_scm(pr_id=None)
        scm.add_socket_comments("s", "o", {})
        client.request.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])
