"""Regression tests for CE-381: orphaned tags and empty tables in PR comments.

A whitespace-only line closes a CommonMark HTML block. When one lands inside the
alerts table the closing tags after it stop being markup, and since they are
indented four or more spaces GitHub renders them as a literal code block reading
`</blockquote></details>`. Separately, a comment whose alerts were all resolved or
ignored used to keep its "Caution" banner above a table with no rows.
"""

from dataclasses import dataclass

import pytest

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

    def test_copy_is_provider_neutral(self):
        body = Messages.security_comment_template(
            _make_diff([_make_alert()]), _FakeConfig(scm="gitlab")
        )
        assert "Socket for GitHub" not in body
        assert "Learn more about [Socket]" in body


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

    def test_qualified_scoped_package_ignore_matches_comment_marker(self):
        security = _security_comment_with([
            _make_alert(
                pkg_name="@socketsecurity/example",
                purl="pkg:npm/@socketsecurity/example@4.17.21",
            )
        ])
        comments = {
            "security": security,
            "ignore": [_make_comment(
                "SocketSecurity ignore npm/@socketsecurity/example@4.17.21",
                comment_id=2,
            )],
        }

        assert "No dependency alerts to report" in Comments.process_security_comment(security, comments)

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

SCOPED_LEGACY_COMMENT = """<!-- socket-security-comment-actions -->

<!-- start-socket-alerts-table -->
|Alert|Package|Introduced by|Manifest File|CI|
|:---|:---|:---|:---|:---|
|Known Malware|[npm/@socketsecurity/example@1.0.0](https://socket.dev/z)|example|package.json|:no_entry_sign:|
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

    def test_scoped_package_row_does_not_raise(self):
        """A scoped name carries its own "@", so the split must come from the right."""
        security = _make_comment(SCOPED_LEGACY_COMMENT)
        comments = {"security": security, "ignore": []}

        new_body = Comments.process_security_comment(security, comments)

        assert "npm/@socketsecurity/example@1.0.0" in new_body

    def test_scoped_package_row_is_ignorable_both_ways(self):
        for command in (
            "SocketSecurity ignore npm/@socketsecurity/example@1.0.0",
            "SocketSecurity ignore @socketsecurity/example@1.0.0",
        ):
            security = _make_comment(SCOPED_LEGACY_COMMENT)
            comments = {"security": security, "ignore": [_make_comment(command, comment_id=2)]}

            new_body = Comments.process_security_comment(security, comments)

            assert "No dependency alerts to report" in new_body, command


class TestExtractReportUrl:
    def test_strips_the_action_filter(self):
        url = Comments.extract_report_url(
            "[View full report](https://socket.dev/report/abc?action=error%2Cwarn)"
        )
        assert url == "https://socket.dev/report/abc"

    def test_returns_empty_when_absent(self):
        assert Comments.extract_report_url("no link here") == ""


# --- Escaping repo-derived values ---------------------------------------------
#
# Manifest paths and sources are file paths inside the customer's repository, so
# anyone who can open a pull request controls them: a directory named
# `![x](https://host/p.png)` holding a manifest puts that markup into a comment
# posted by a trusted integration. GitHub and GitLab sanitize comment HTML, so the
# exposure is external resource loading, phishing links and content spoofing
# rather than script execution.


@dataclass
class _RepoConfig(_FakeConfig):
    """A config that reaches the branch which embeds the path verbatim.

    Without repo/branch, get_manifest_file_url returns "" or a percent-encoded
    Socket link, and the path never lands in the comment -- so a test using the
    bare config asserts nothing.
    """
    repo: str = "acme/widgets"
    branch: str = "main"


HOSTILE_PATHS = {
    "image": "![x](https://evil.example/p.png)/package.json",
    "link": "[click me](https://evil.example)/package.json",
    "raw_tag": "<img src=x onerror=alert(1)>/package.json",
    "backtick": "`code`/package.json",
    "pipe": "a|b/package.json",
    "quote": 'a" onmouseover="x/package.json',
    "comment_close": "x-->y/package.json",
}


def _rendered_with_path(path: str) -> str:
    return Messages.security_comment_template(
        _make_diff([_make_alert(manifests=path)]), _RepoConfig()
    )


def test_the_hostile_path_actually_reaches_the_comment():
    """Guards the fixture itself: if the path stops being rendered, the escaping
    tests below would pass while asserting nothing."""
    body = _rendered_with_path("sentinel-path/package.json")

    assert "sentinel-path" in body


@pytest.mark.parametrize("name,path", sorted(HOSTILE_PATHS.items()))
def test_hostile_manifest_path_cannot_introduce_markup(name, path):
    """In the rendered comment the path only ever lands inside an href, where
    Markdown is inert. The property that matters there is that the value cannot
    open a tag or close the attribute -- see create_sources for the context where
    Markdown itself is live."""
    body = _rendered_with_path(path)

    rendered = [ln for ln in body.split("\n") if "Manifest File" in ln][0]
    value = rendered.split('href="', 1)[1].split('"', 1)[0]

    for char in ("<", ">", '"'):
        assert char not in value, f"{char!r} survived into the href: {value!r}"
    assert_html_block_intact(body)


def test_quote_in_a_path_cannot_escape_the_href():
    body = _rendered_with_path('a" onmouseover="x/package.json')

    assert "&quot;" in body
    assert 'href="https://github.com/acme/widgets/blob/main/a" ' not in body


def test_hostile_package_name_cannot_close_the_alert_marker():
    body = Messages.security_comment_template(
        _make_diff([_make_alert(pkg_name="evil-->x")]), _FakeConfig()
    )

    # Exactly the terminator the CLI wrote, and no stray one inside the value.
    for line in body.split("\n"):
        if "socket-alert-" in line:
            assert line.count("-->") == 1, line


def test_alert_text_from_the_api_is_escaped():
    body = Messages.security_comment_template(
        _make_diff([_make_alert(description="<script>alert(1)</script>")]), _FakeConfig()
    )

    assert "<script>" not in body
    assert "&lt;script&gt;" in body


@pytest.mark.parametrize("name,path", sorted(HOSTILE_PATHS.items()))
def test_hostile_path_still_round_trips_through_the_ignore_parser(name, path):
    """Escaping must not break reading the comment back.

    The renderer and the comment parser are two halves of one loop: a comment the
    CLI writes is re-read on the next run to apply ignore commands. An escaping
    choice the parser cannot read would silently stop ignores working.
    """
    security = _make_comment(_rendered_with_path(path))
    comments = {
        "security": security,
        "ignore": [_make_comment("SocketSecurity ignore npm/lodash@4.17.21", comment_id=2)],
    }

    new_body = Comments.process_security_comment(security, comments)

    assert "No dependency alerts to report" in new_body


class TestCreateSourcesEscaping:
    """create_sources' md style emits <li> into rendered Markdown, so unlike the
    href context a path there IS interpreted as Markdown."""

    def _md(self, path: str) -> str:
        alert = _make_alert()
        alert.introduced_by = [("direct", path)]
        manifest_str, _ = Messages.create_sources(alert, "md")
        return manifest_str

    @pytest.mark.parametrize("name,path", sorted(HOSTILE_PATHS.items()))
    def test_md_style_escapes_the_path(self, name, path):
        """Escaping stops the value opening a tag. Markdown inside the value is
        inert because GFM does not parse Markdown within a raw HTML block, which
        is why escaping rather than code spans is the right tool for <li>."""
        out = self._md(path)

        assert "<img src=x onerror=alert(1)>" not in out
        # Structure intact: exactly the one element create_sources wrote.
        assert out.count("<li>") == 1 and out.count("</li>") == 1
        inner = out[out.index("<li>") + 4 : out.index("</li>")]
        for char in ("<", ">"):
            assert char not in inner, f"{char!r} survived into the list item: {inner!r}"

    def test_plain_style_is_left_verbatim(self):
        """Slack, Jira and the console do not render HTML."""
        alert = _make_alert()
        alert.introduced_by = [("direct", "<img src=x>/package.json")]

        manifest_str, _ = Messages.create_sources(alert, "plain")

        assert "<img src=x>/package.json" in manifest_str
