"""Tests for Bitbucket SCM support."""
import base64
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from socketsecurity.core.scm.bitbucket import Bitbucket, BitbucketConfig


def _make_config(pr_id="42", api_url="https://api.bitbucket.org/2.0"):
    return BitbucketConfig(
        api_url=api_url,
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


def _json_response(payload):
    resp = MagicMock()
    resp.json.return_value = payload
    return resp


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

    @patch.dict(os.environ, {"BITBUCKET_TOKEN": "t"}, clear=True)
    def test_from_env_missing_workspace_repo_exits(self):
        """Credentials present but no workspace/repo info — fail fast rather
        than building 404-bound URLs deeper in the request flow."""
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


class TestSplitAbsoluteUrl:
    def test_splits_origin_and_path(self):
        origin, path = Bitbucket._split_absolute_url(
            "https://api.bitbucket.org/2.0/repositories/acme/widgets/pullrequests/42/comments?page=2"
        )
        assert origin == "https://api.bitbucket.org"
        assert path == "2.0/repositories/acme/widgets/pullrequests/42/comments?page=2"

    def test_no_query_string(self):
        origin, path = Bitbucket._split_absolute_url(
            "https://bitbucket.example.com/rest/api/1.0/foo"
        )
        assert origin == "https://bitbucket.example.com"
        assert path == "rest/api/1.0/foo"

    def test_reconstructed_url_matches_clicliclient_join(self):
        """CliClient does f'{base_url}/{path}' — verify our split round-trips."""
        original = "https://api.bitbucket.org/2.0/foo/bar?x=1&y=2"
        origin, path = Bitbucket._split_absolute_url(original)
        assert f"{origin}/{path}" == original


class TestBitbucketPagination:
    def test_follows_next_url_via_origin_split(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        # Use Socket-style bodies so check_for_socket_comments keeps them and
        # we can observe that BOTH pages were fetched.
        page1 = {
            "values": [
                {
                    "id": 1,
                    "content": {"raw": "socket-security-comment-actions: page1"},
                    "user": {"nickname": "alice", "uuid": "{u-1}"},
                }
            ],
            "next": (
                "https://api.bitbucket.org/2.0/repositories/acme/widgets"
                "/pullrequests/42/comments?page=2"
            ),
        }
        page2 = {
            "values": [
                {
                    "id": 2,
                    "content": {"raw": "socket-overview-comment-actions: page2"},
                    "user": {"nickname": "bob", "uuid": "{u-2}"},
                }
            ],
        }
        scm.client.request.side_effect = [_json_response(page1), _json_response(page2)]

        result = scm.get_comments_for_pr()

        # Both pages were scanned: the security comment came from page 1 and
        # the overview comment from page 2.
        assert "security" in result and result["security"].body.endswith("page1")
        assert "overview" in result and result["overview"].body.endswith("page2")

        # First call: relative path against Bitbucket API base.
        first_call = scm.client.request.call_args_list[0]
        assert first_call.kwargs["base_url"] == "https://api.bitbucket.org/2.0"
        assert "pagelen=100" in first_call.kwargs["path"]

        # Second call: origin pulled out of the absolute next URL — must NOT
        # be empty (which would fall back to Socket's API URL in CliClient).
        second_call = scm.client.request.call_args_list[1]
        assert second_call.kwargs["base_url"] == "https://api.bitbucket.org"
        assert second_call.kwargs["base_url"]  # non-empty -> avoids fallback
        assert second_call.kwargs["path"].startswith(
            "2.0/repositories/acme/widgets/pullrequests/42/comments"
        )
        assert "page=2" in second_call.kwargs["path"]

    def test_stops_when_no_next(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        scm.client.request.return_value = _json_response({"values": []})
        scm.get_comments_for_pr()
        assert scm.client.request.call_count == 1

    def test_no_pr_skips_fetch(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config(pr_id=None))
        result = scm.get_comments_for_pr()
        assert result == {}
        scm.client.request.assert_not_called()

    def test_error_response_breaks_loop(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        scm.client.request.return_value = _json_response(
            {"type": "error", "error": {"message": "boom"}}
        )
        result = scm.get_comments_for_pr()
        assert result == {}
        assert scm.client.request.call_count == 1


class TestHasThumbsupReaction:
    def test_detects_processed_marker(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        scm.client.request.return_value = _json_response(
            {"content": {"raw": f"some body\n\n{Bitbucket.PROCESSED_MARKER}"}}
        )
        assert scm.has_thumbsup_reaction(123) is True

    def test_returns_false_when_marker_absent(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        scm.client.request.return_value = _json_response(
            {"content": {"raw": "plain comment with no marker"}}
        )
        assert scm.has_thumbsup_reaction(123) is False

    def test_returns_false_when_no_pr(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config(pr_id=None))
        assert scm.has_thumbsup_reaction(123) is False
        scm.client.request.assert_not_called()

    def test_returns_false_on_request_exception(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        scm.client.request.side_effect = RuntimeError("network down")
        assert scm.has_thumbsup_reaction(123) is False


class TestMarkCommentProcessed:
    def test_appends_marker_and_updates(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        comment = MagicMock(id=99, body="original body")
        scm._mark_comment_processed(comment)
        call = scm.client.request.call_args
        assert call.kwargs["method"] == "PUT"
        payload = json.loads(call.kwargs["payload"])
        assert payload["content"]["raw"].startswith("original body")
        assert Bitbucket.PROCESSED_MARKER in payload["content"]["raw"]

    def test_is_idempotent_when_marker_already_present(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        comment = MagicMock(
            id=99, body=f"already processed\n\n{Bitbucket.PROCESSED_MARKER}"
        )
        scm._mark_comment_processed(comment)
        scm.client.request.assert_not_called()

    def test_swallows_update_errors(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        scm.client.request.side_effect = RuntimeError("boom")
        comment = MagicMock(id=99, body="x")
        # Should not raise.
        scm._mark_comment_processed(comment)


class TestSocketCommentClassification:
    def test_get_comments_runs_check_for_socket_comments(self):
        """Normalized comments must flow through Comments.check_for_socket_comments
        so the overview/security/ignore keys are populated for downstream code."""
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        # A Socket-style "ignore" comment body.
        page = {
            "values": [
                {
                    "id": 1,
                    "content": {"raw": "@SocketSecurity ignore npm/foo@1.0.0"},
                    "user": {"nickname": "alice", "uuid": "{u-1}"},
                }
            ]
        }
        scm.client.request.return_value = _json_response(page)
        result = scm.get_comments_for_pr()
        # Comments.check_for_socket_comments populates the "ignore" bucket.
        assert "ignore" in result
        assert any(
            "SocketSecurity ignore" in c.body for c in result["ignore"]
        )


class TestCommentBodyCache:
    def test_has_thumbsup_uses_cache_after_fetch(self):
        """get_comments_for_pr should populate the body cache so subsequent
        has_thumbsup_reaction calls don't issue extra GETs per ignore comment."""
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        page = {
            "values": [
                {
                    "id": 1,
                    "content": {"raw": f"@SocketSecurity ignore npm/foo@1.0.0\n\n{Bitbucket.PROCESSED_MARKER}"},
                    "user": {"nickname": "alice", "uuid": "{u-1}"},
                },
                {
                    "id": 2,
                    "content": {"raw": "@SocketSecurity ignore npm/bar@2.0.0"},
                    "user": {"nickname": "bob", "uuid": "{u-2}"},
                },
            ]
        }
        scm.client.request.return_value = _json_response(page)
        scm.get_comments_for_pr()
        calls_after_fetch = scm.client.request.call_count

        # Both should resolve from cache — no additional API calls.
        assert scm.has_thumbsup_reaction(1) is True
        assert scm.has_thumbsup_reaction(2) is False
        assert scm.client.request.call_count == calls_after_fetch

    def test_has_thumbsup_falls_back_to_api_when_not_cached(self):
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        scm.client.request.return_value = _json_response(
            {"content": {"raw": f"body\n\n{Bitbucket.PROCESSED_MARKER}"}}
        )
        # ID not seen by get_comments_for_pr — falls back to GET.
        assert scm.has_thumbsup_reaction(999) is True
        scm.client.request.assert_called_once()

    def test_mark_comment_processed_updates_cache(self):
        """After marking, the cache reflects the new body so a subsequent
        has_thumbsup_reaction in the same run sees it without re-fetching."""
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        comment = MagicMock(id=42, body="original")
        scm._mark_comment_processed(comment)
        assert scm._comment_body_cache[42].endswith(Bitbucket.PROCESSED_MARKER)
        # And subsequent reaction check is a cache hit.
        scm.client.request.reset_mock()
        assert scm.has_thumbsup_reaction(42) is True
        scm.client.request.assert_not_called()


class TestNullSafePaginationValues:
    def test_handles_null_values_field(self):
        """If Bitbucket returns {"values": null} instead of omitting the key,
        the for-loop must not blow up."""
        scm = Bitbucket(client=MagicMock(), config=_make_config())
        scm.client.request.return_value = _json_response({"values": None})
        # Should not raise.
        result = scm.get_comments_for_pr()
        assert result == {}


if __name__ == "__main__":
    pytest.main([__file__])
