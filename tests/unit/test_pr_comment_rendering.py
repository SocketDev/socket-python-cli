"""Regression tests for CE-381: orphaned tags and empty tables in PR comments.

A whitespace-only line closes a CommonMark HTML block. When one lands inside the
alerts table the closing tags after it stop being markup, and since they are
indented four or more spaces GitHub renders them as a literal code block reading
`</blockquote></details>`. Separately, a comment whose alerts were all resolved or
ignored used to keep its "Caution" banner above a table with no rows.
"""

from dataclasses import dataclass

from socketsecurity.core.classes import Comment, Diff, Issue
from socketsecurity.core.messages import Messages
from socketsecurity.core.scm_comments import Comments


@dataclass
class _FakeConfig:
    disable_ignore: bool = False
    scm: str = "github"


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


def _make_diff(alerts: list) -> Diff:
    diff = Diff()
    diff.id = "test-scan-id"
    diff.diff_url = "https://socket.dev/report/abc"
    diff.new_alerts = alerts
    return diff


def _make_comment(body: str, comment_id: int = 1) -> Comment:
    return Comment(
        id=comment_id,
        body=body,
        body_list=body.split("\n"),
        reactions={"+1": 0},
        user={"login": "test-user", "id": 123},
    )


def assert_html_block_intact(body: str) -> None:
    """Fails if the body can break out of its HTML block when rendered."""
    for number, line in enumerate(body.split("\n"), 1):
        assert line == "" or line.strip(), (
            f"line {number} is whitespace-only, which closes the HTML block: {line!r}"
        )
        indent = len(line) - len(line.lstrip())
        assert indent < 4, (
            f"line {number} is indented {indent} spaces and would render as a "
            f"code block if the HTML block ever closes early: {line!r}"
        )


# --- normalize_comment_html ---

class TestNormalizeCommentHtml:
    def test_drops_whitespace_only_lines(self):
        result = Messages.normalize_comment_html("<p>a</p>\n    \n<p>b</p>")
        assert result == "<p>a</p>\n<p>b</p>"

    def test_preserves_genuinely_empty_separator_lines(self):
        result = Messages.normalize_comment_html("<!-- marker -->\n\n> text")
        assert result == "<!-- marker -->\n\n> text"

    def test_caps_indentation_below_code_block_threshold(self):
        result = Messages.normalize_comment_html("        </details>")
        assert result == "   </details>"

    def test_preserves_trailing_markdown_line_breaks(self):
        result = Messages.normalize_comment_html("> **Caution**  ")
        assert result == "> **Caution**  "


# --- inline_html_text ---

class TestInlineHtmlText:
    def test_collapses_newlines(self):
        assert Messages.inline_html_text("one\n\ntwo") == "one two"

    def test_handles_none(self):
        assert Messages.inline_html_text(None) == ""


# --- Generated comment bodies ---

class TestSecurityCommentTemplateRendering:
    def test_security_alert_row_is_render_safe(self):
        body = Messages.security_comment_template(_make_diff([_make_alert()]), _FakeConfig())
        assert_html_block_intact(body)

    def test_render_safe_when_ignore_instructions_disabled(self):
        """The empty ignore block used to leave a whitespace-only line behind."""
        body = Messages.security_comment_template(
            _make_diff([_make_alert()]), _FakeConfig(disable_ignore=True)
        )
        assert_html_block_intact(body)
        assert "</blockquote>" in body
        assert "@SocketSecurity ignore" not in body

    def test_license_row_render_safe_when_ignore_instructions_disabled(self):
        body = Messages.security_comment_template(
            _make_diff([_make_alert(type="licenseSpdxDisj", title="LGPL-3.0")]),
            _FakeConfig(disable_ignore=True),
        )
        assert_html_block_intact(body)
        assert "License Policy Violation" in body

    def test_multiline_alert_text_is_flattened(self):
        body = Messages.security_comment_template(
            _make_diff([
                _make_alert(description="Line one.\n\nLine two.", suggestion="Do this.\nThen that.")
            ]),
            _FakeConfig(),
        )
        assert_html_block_intact(body)
        assert "<p><strong>Note:</strong> Line one. Line two.</p>" in body
        assert "Do this. Then that." in body

    def test_license_finding_text_is_flattened(self):
        body = Messages.security_comment_template(
            _make_diff([_make_alert(type="licenseSpdxDisj", title="LGPL-3.0\n\nAND MIT")]),
            _FakeConfig(),
        )
        assert_html_block_intact(body)
        assert "<li>LGPL-3.0 AND MIT</li>" in body

    def test_alert_markers_are_preserved(self):
        body = Messages.security_comment_template(_make_diff([_make_alert()]), _FakeConfig())
        assert "<!-- start-socket-alert-lodash@4.17.21 -->" in body
        assert "<!-- end-socket-alert-lodash@4.17.21 -->" in body


class TestSecurityCommentTemplateWithNoAlerts:
    def test_no_alerts_omits_the_empty_table(self):
        body = Messages.security_comment_template(_make_diff([]), _FakeConfig())
        assert "<table>" not in body
        assert "Caution" not in body
        assert "No dependency alerts to report" in body

    def test_no_alerts_keeps_the_comment_discoverable(self):
        """The marker has to survive so a later commit updates this comment
        instead of posting a second one."""
        body = Messages.security_comment_template(_make_diff([]), _FakeConfig())
        found = Comments.check_for_socket_comments({1: _make_comment(body)})
        assert "security" in found

    def test_no_alerts_keeps_the_report_link(self):
        body = Messages.security_comment_template(_make_diff([]), _FakeConfig())
        assert "[View full report](https://socket.dev/report/abc)" in body

    def test_no_alerts_without_report_url_omits_the_link(self):
        diff = Diff()
        diff.id = "test-scan-id"
        diff.new_alerts = []
        body = Messages.security_comment_template(diff, _FakeConfig())
        assert "View full report" not in body


# --- Ignore round trip ---

def _security_comment_with(alerts: list, config=None) -> Comment:
    body = Messages.security_comment_template(_make_diff(alerts), config or _FakeConfig())
    return _make_comment(body)


class TestProcessUpdatedSecurityComment:
    def _two_alert_comment(self) -> Comment:
        return _security_comment_with([
            _make_alert(),
            _make_alert(pkg_name="express", pkg_version="4.18.2", purl="pkg:npm/express@4.18.2"),
        ])

    def test_partial_ignore_keeps_remaining_alert_render_safe(self):
        security = self._two_alert_comment()
        ignore = _make_comment("SocketSecurity ignore lodash@4.17.21", comment_id=2)
        comments = {"security": security, "ignore": [ignore]}

        new_body = Comments.process_security_comment(security, comments)

        assert_html_block_intact(new_body)
        assert "start-socket-alert-express@4.18.2" in new_body
        assert "start-socket-alert-lodash@4.17.21" not in new_body

    def test_ignore_all_collapses_to_the_no_alerts_body(self):
        security = self._two_alert_comment()
        ignore = _make_comment("SocketSecurity ignore-all", comment_id=2)
        comments = {"security": security, "ignore": [ignore]}

        new_body = Comments.process_security_comment(security, comments)

        assert "<table>" not in new_body
        assert "No dependency alerts to report" in new_body
        assert "[View full report](https://socket.dev/report/abc)" in new_body

    def test_ignoring_every_alert_individually_collapses_too(self):
        security = self._two_alert_comment()
        comments = {
            "security": security,
            "ignore": [
                _make_comment("SocketSecurity ignore lodash@4.17.21", comment_id=2),
                _make_comment("SocketSecurity ignore express@4.18.2", comment_id=3),
            ],
        }

        new_body = Comments.process_security_comment(security, comments)

        assert "No dependency alerts to report" in new_body

    def test_no_ignore_commands_leaves_alerts_in_place(self):
        security = self._two_alert_comment()
        comments = {"security": security, "ignore": []}

        new_body = Comments.process_security_comment(security, comments)

        assert "start-socket-alert-lodash@4.17.21" in new_body
        assert "start-socket-alert-express@4.18.2" in new_body

    def test_collapsed_body_is_stable_when_reprocessed(self):
        security = self._two_alert_comment()
        ignore = _make_comment("SocketSecurity ignore-all", comment_id=2)
        comments = {"security": security, "ignore": [ignore]}

        first = Comments.process_security_comment(security, comments)
        comments["security"] = _make_comment(first)
        second = Comments.process_security_comment(comments["security"], comments)

        assert first == second


LEGACY_COMMENT = """<!-- socket-security-comment-actions -->

<!-- start-socket-alerts-table -->
|Alert|Package|Introduced by|Manifest File|CI|
|:---|:---|:---|:---|:---|
|Known Malware|[npm/lodash@4.17.21](https://socket.dev/x)|lodash|package.json|:no_entry_sign:|
|Known Malware|[npm/express@4.18.2](https://socket.dev/y)|express|package.json|:no_entry_sign:|
<!-- end-socket-alerts-table -->

[View full report](https://socket.dev/report/legacy?action=error%2Cwarn)
"""


class TestProcessOriginalSecurityComment:
    def test_partial_ignore_keeps_remaining_row(self):
        security = _make_comment(LEGACY_COMMENT)
        comments = {
            "security": security,
            "ignore": [_make_comment("SocketSecurity ignore npm/lodash@4.17.21", comment_id=2)],
        }

        new_body = Comments.process_security_comment(security, comments)

        assert "npm/express@4.18.2" in new_body
        assert "npm/lodash@4.17.21" not in new_body

    def test_ignore_all_collapses_to_the_no_alerts_body(self):
        security = _make_comment(LEGACY_COMMENT)
        comments = {
            "security": security,
            "ignore": [_make_comment("SocketSecurity ignore-all", comment_id=2)],
        }

        new_body = Comments.process_security_comment(security, comments)

        assert "|Alert|Package|" not in new_body
        assert "No dependency alerts to report" in new_body
        assert "[View full report](https://socket.dev/report/legacy)" in new_body


class TestExtractReportUrl:
    def test_strips_the_action_filter(self):
        url = Comments.extract_report_url(
            "[View full report](https://socket.dev/report/abc?action=error%2Cwarn)"
        )
        assert url == "https://socket.dev/report/abc"

    def test_returns_empty_when_absent(self):
        assert Comments.extract_report_url("no link here") == ""
