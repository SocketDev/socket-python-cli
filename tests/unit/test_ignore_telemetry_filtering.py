"""Tests for the +1 reaction dedup logic used to filter ignore comments for telemetry."""

from unittest.mock import Mock

from socketsecurity.core.classes import Comment
from socketsecurity.core.scm_comments import Comments


def _make_comment(body: str, thumbs_up: int = 0, comment_id: int = 1, user: dict | None = None) -> Comment:
    return Comment(
        id=comment_id,
        body=body,
        body_list=body.split("\n"),
        reactions={"+1": thumbs_up},
        user=user or {"login": "test-user", "id": 123},
    )


def _filter_unprocessed(comments: list[Comment], scm=None) -> list[Comment]:
    """Mirrors the _is_unprocessed logic in socketcli.py."""
    def _is_unprocessed(c):
        if getattr(c, "reactions", {}).get("+1"):
            return False
        if hasattr(scm, "has_thumbsup_reaction") and scm.has_thumbsup_reaction(c.id):
            return False
        return True

    return [c for c in comments if _is_unprocessed(c)]


class TestUnprocessedIgnoreFiltering:
    def test_returns_comments_without_thumbsup(self):
        comments = [
            _make_comment("SocketSecurity ignore npm/lodash@4.17.21", thumbs_up=0, comment_id=1),
            _make_comment("SocketSecurity ignore npm/express@4.18.2", thumbs_up=0, comment_id=2),
        ]
        result = _filter_unprocessed(comments)
        assert len(result) == 2

    def test_excludes_comments_with_thumbsup(self):
        comments = [
            _make_comment("SocketSecurity ignore npm/lodash@4.17.21", thumbs_up=1, comment_id=1),
            _make_comment("SocketSecurity ignore npm/express@4.18.2", thumbs_up=0, comment_id=2),
        ]
        result = _filter_unprocessed(comments)
        assert len(result) == 1
        assert result[0].id == 2

    def test_returns_empty_when_all_processed(self):
        comments = [
            _make_comment("SocketSecurity ignore npm/lodash@4.17.21", thumbs_up=1, comment_id=1),
            _make_comment("SocketSecurity ignore-all", thumbs_up=2, comment_id=2),
        ]
        result = _filter_unprocessed(comments)
        assert len(result) == 0

    def test_handles_missing_reactions_attr(self):
        c = Comment(id=1, body="SocketSecurity ignore npm/foo@1.0.0", body_list=["SocketSecurity ignore npm/foo@1.0.0"])
        # No reactions attribute set at all
        result = _filter_unprocessed([c])
        assert len(result) == 1

    def test_handles_empty_reactions_dict(self):
        c = _make_comment("SocketSecurity ignore npm/foo@1.0.0", comment_id=1)
        c.reactions = {}
        result = _filter_unprocessed([c])
        assert len(result) == 1

    def test_handles_reactions_with_thumbsup_zero(self):
        c = _make_comment("SocketSecurity ignore npm/foo@1.0.0", thumbs_up=0, comment_id=1)
        result = _filter_unprocessed([c])
        assert len(result) == 1


class TestUnprocessedIgnoreFilteringWithScmFallback:
    """Tests for the has_thumbsup_reaction fallback path (GitLab)."""

    def test_scm_fallback_excludes_processed_comments(self):
        """When inline reactions['+1'] is 0 but scm says it has thumbsup, exclude it."""
        comments = [
            _make_comment("SocketSecurity ignore npm/lodash@4.17.21", thumbs_up=0, comment_id=1),
            _make_comment("SocketSecurity ignore npm/express@4.18.2", thumbs_up=0, comment_id=2),
        ]
        scm = Mock()
        scm.has_thumbsup_reaction = Mock(side_effect=lambda cid: cid == 1)

        result = _filter_unprocessed(comments, scm=scm)
        assert len(result) == 1
        assert result[0].id == 2

    def test_scm_fallback_not_called_when_inline_thumbsup_present(self):
        """When inline reactions['+1'] is truthy, scm.has_thumbsup_reaction should not be called."""
        comments = [
            _make_comment("SocketSecurity ignore npm/lodash@4.17.21", thumbs_up=1, comment_id=1),
        ]
        scm = Mock()
        scm.has_thumbsup_reaction = Mock(return_value=False)

        result = _filter_unprocessed(comments, scm=scm)
        assert len(result) == 0
        scm.has_thumbsup_reaction.assert_not_called()

    def test_scm_without_has_thumbsup_reaction_skips_fallback(self):
        """When scm doesn't have has_thumbsup_reaction (e.g. GitHub), only inline check runs."""
        comments = [
            _make_comment("SocketSecurity ignore npm/foo@1.0.0", thumbs_up=0, comment_id=1),
        ]
        scm = Mock(spec=[])  # no methods at all

        result = _filter_unprocessed(comments, scm=scm)
        assert len(result) == 1

    def test_scm_fallback_returns_all_unprocessed(self):
        """When scm says none have thumbsup, all are returned."""
        comments = [
            _make_comment("SocketSecurity ignore npm/foo@1.0.0", thumbs_up=0, comment_id=1),
            _make_comment("SocketSecurity ignore npm/bar@2.0.0", thumbs_up=0, comment_id=2),
        ]
        scm = Mock()
        scm.has_thumbsup_reaction = Mock(return_value=False)

        result = _filter_unprocessed(comments, scm=scm)
        assert len(result) == 2


class TestUnprocessedIgnoreFilteringWithCommentsParsing:
    """Integration: filter unprocessed comments, then parse ignore options."""

    def test_only_new_artifacts_are_parsed(self):
        comments = [
            _make_comment("SocketSecurity ignore npm/lodash@4.17.21", thumbs_up=1, comment_id=1),
            _make_comment("SocketSecurity ignore npm/express@4.18.2", thumbs_up=0, comment_id=2),
            _make_comment("SocketSecurity ignore npm/axios@1.6.0", thumbs_up=0, comment_id=3),
        ]
        unprocessed = _filter_unprocessed(comments)
        unprocessed_comments = {"ignore": unprocessed}
        ignore_all, ignore_commands = Comments.get_ignore_options(unprocessed_comments)

        assert not ignore_all
        assert ("npm/express", "4.18.2") in ignore_commands
        assert ("npm/axios", "1.6.0") in ignore_commands
        assert ("npm/lodash", "4.17.21") not in ignore_commands

    def test_ignore_all_from_unprocessed(self):
        comments = [
            _make_comment("SocketSecurity ignore npm/lodash@4.17.21", thumbs_up=1, comment_id=1),
            _make_comment("SocketSecurity ignore-all", thumbs_up=0, comment_id=2),
        ]
        unprocessed = _filter_unprocessed(comments)
        unprocessed_comments = {"ignore": unprocessed}
        ignore_all, ignore_commands = Comments.get_ignore_options(unprocessed_comments)

        assert ignore_all

    def test_no_unprocessed_means_no_telemetry(self):
        comments = [
            _make_comment("SocketSecurity ignore npm/lodash@4.17.21", thumbs_up=1, comment_id=1),
            _make_comment("SocketSecurity ignore npm/express@4.18.2", thumbs_up=2, comment_id=2),
        ]
        unprocessed = _filter_unprocessed(comments)
        assert len(unprocessed) == 0


def _build_event(comment, ignore_all=False, ignore_commands=None, artifact_input=None, artifact_purl=None):
    """Mirrors the event construction logic in socketcli.py."""
    from datetime import datetime, timezone
    from uuid import uuid4

    user = getattr(comment, "user", None) or getattr(comment, "author", None) or {}
    shared_fields = {
        "event_kind": "user-action",
        "client_action": "ignore",
        "alert_action": "error",
        "event_sender_created_at": datetime.now(timezone.utc).isoformat(),
        "vcs_provider": "github",
        "owner": "test-owner",
        "repo": "test-owner/test-repo",
        "pr_number": 1,
        "ignore_all": ignore_all,
        "sender_name": user.get("login") or user.get("username", ""),
        "sender_id": str(user.get("id", "")),
    }
    if artifact_input:
        return {**shared_fields, "event_id": str(uuid4()), "artifact_input": artifact_input}
    if artifact_purl:
        return {**shared_fields, "event_id": str(uuid4()), "artifact_purl": artifact_purl}
    return {**shared_fields, "event_id": str(uuid4())}


class TestTelemetryEventPayloadShape:
    """Tests that telemetry event payloads contain the required fields."""

    def test_per_artifact_event_has_required_fields(self):
        c = _make_comment("SocketSecurity ignore npm/lodash@4.17.21", user={"login": "alice", "id": 1})
        event = _build_event(c, artifact_input="npm/lodash@4.17.21")

        assert event["event_kind"] == "user-action"
        assert event["client_action"] == "ignore"
        assert event["alert_action"] == "error"
        assert event["vcs_provider"] == "github"
        assert event["sender_name"] == "alice"
        assert event["sender_id"] == "1"
        assert event["artifact_input"] == "npm/lodash@4.17.21"
        assert "event_id" in event
        assert "event_sender_created_at" in event

    def test_ignore_all_event_has_required_fields(self):
        c = _make_comment("SocketSecurity ignore-all", user={"login": "bob", "id": 2})
        event = _build_event(c, ignore_all=True)

        assert event["event_kind"] == "user-action"
        assert event["client_action"] == "ignore"
        assert event["alert_action"] == "error"
        assert event["ignore_all"] is True
        assert event["sender_name"] == "bob"
        assert "artifact_input" not in event
        assert "artifact_purl" not in event

    def test_push_flow_event_uses_artifact_purl(self):
        c = _make_comment("SocketSecurity ignore npm/lodash@4.17.21", user={"login": "alice", "id": 1})
        event = _build_event(c, artifact_purl="pkg:npm/lodash@4.17.21")

        assert event["artifact_purl"] == "pkg:npm/lodash@4.17.21"
        assert event["alert_action"] == "error"
        assert "artifact_input" not in event

    def test_gitlab_author_populates_sender(self):
        c = Comment(
            id=1, body="SocketSecurity ignore npm/foo@1.0.0",
            body_list=["SocketSecurity ignore npm/foo@1.0.0"],
            reactions={"+1": 0},
            author={"username": "gitlab-dev", "id": 42},
        )
        event = _build_event(c, artifact_input="npm/foo@1.0.0")

        assert event["sender_name"] == "gitlab-dev"
        assert event["sender_id"] == "42"
