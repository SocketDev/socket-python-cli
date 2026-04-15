"""Tests for the --disable-ignore flag."""

import pytest
from dataclasses import dataclass

from socketsecurity.config import CliConfig
from socketsecurity.core.classes import Comment, Diff, Issue
from socketsecurity.core.messages import Messages
from socketsecurity.core.scm_comments import Comments


# --- CLI flag parsing tests ---

class TestDisableIgnoreFlag:
    def test_flag_defaults_to_false(self):
        config = CliConfig.from_args(["--api-token", "test"])
        assert config.disable_ignore is False

    def test_flag_parsed_with_dashes(self):
        config = CliConfig.from_args(["--api-token", "test", "--disable-ignore"])
        assert config.disable_ignore is True

    def test_flag_parsed_with_underscores(self):
        config = CliConfig.from_args(["--api-token", "test", "--disable_ignore"])
        assert config.disable_ignore is True

    def test_flag_independent_of_disable_blocking(self):
        config = CliConfig.from_args([
            "--api-token", "test",
            "--disable-ignore",
            "--disable-blocking",
        ])
        assert config.disable_ignore is True
        assert config.disable_blocking is True


# --- Alert suppression tests ---

def _make_alert(**overrides) -> Issue:
    defaults = dict(
        pkg_name="lodash",
        pkg_version="4.17.21",
        pkg_type="npm",
        severity="high",
        title="Known Malware",
        description="Test description",
        type="malware",
        url="https://socket.dev/test",
        manifests="package.json",
        props={},
        key="test-key",
        purl="pkg:npm/lodash@4.17.21",
        error=True,
        warn=False,
        ignore=False,
        monitor=False,
        suggestion="Remove this package",
        next_step_title="Next steps",
        emoji="🚨",
    )
    defaults.update(overrides)
    return Issue(**defaults)


def _make_comment(body: str, comment_id: int = 1) -> Comment:
    return Comment(
        id=comment_id,
        body=body,
        body_list=body.split("\n"),
        reactions={"+1": 0},
        user={"login": "test-user", "id": 123},
    )


class TestRemoveAlertsRespectedByFlag:
    """Verify that Comments.remove_alerts behaves correctly so the
    disable_ignore conditional in socketcli.py has the right effect."""

    def test_remove_alerts_suppresses_matching_alert(self):
        """Without --disable-ignore, matching alerts are removed."""
        alert = _make_alert()
        ignore_comment = _make_comment("SocketSecurity ignore npm/lodash@4.17.21")
        comments = Comments.check_for_socket_comments({ignore_comment.id: ignore_comment})
        result = Comments.remove_alerts(comments, [alert])
        assert len(result) == 0

    def test_alerts_preserved_when_no_ignore_comments(self):
        """With --disable-ignore the caller skips remove_alerts entirely,
        which is equivalent to passing empty comments."""
        alert = _make_alert()
        result = Comments.remove_alerts({}, [alert])
        assert len(result) == 1
        assert result[0].pkg_name == "lodash"

    def test_ignore_all_suppresses_all_alerts(self):
        alert1 = _make_alert()
        alert2 = _make_alert(pkg_name="express", pkg_version="4.18.2",
                             purl="pkg:npm/express@4.18.2")
        ignore_comment = _make_comment("SocketSecurity ignore-all")
        comments = Comments.check_for_socket_comments({ignore_comment.id: ignore_comment})
        result = Comments.remove_alerts(comments, [alert1, alert2])
        assert len(result) == 0


# --- Comment output tests ---

@dataclass
class _FakeConfig:
    disable_ignore: bool = False
    scm: str = "github"


class TestSecurityCommentIgnoreInstructions:
    def _make_diff_with_alert(self) -> Diff:
        diff = Diff()
        diff.id = "test-scan-id"
        diff.diff_url = "https://socket.dev/test"
        diff.new_alerts = [_make_alert()]
        return diff

    def test_ignore_instructions_shown_by_default(self):
        diff = self._make_diff_with_alert()
        config = _FakeConfig(disable_ignore=False)
        comment = Messages.security_comment_template(diff, config)
        assert "@SocketSecurity ignore" in comment
        assert "Mark as acceptable risk" in comment

    def test_ignore_instructions_hidden_when_disabled(self):
        diff = self._make_diff_with_alert()
        config = _FakeConfig(disable_ignore=True)
        comment = Messages.security_comment_template(diff, config)
        assert "@SocketSecurity ignore" not in comment
        assert "Mark as acceptable risk" not in comment

    def test_ignore_instructions_shown_when_config_is_none(self):
        diff = self._make_diff_with_alert()
        comment = Messages.security_comment_template(diff, config=None)
        assert "@SocketSecurity ignore" in comment
