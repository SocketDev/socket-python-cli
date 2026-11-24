"""SCM comment events with and without Socket ignore commands."""

import sys
from contextlib import nullcontext
from unittest.mock import MagicMock, Mock

import pytest

from socketsecurity import socketcli
from socketsecurity.core.classes import Comment
from socketsecurity.core.scm.github import Github
from socketsecurity.core.scm.gitlab import Gitlab, GitlabConfig
from socketsecurity.core.scm_comments import Comments

SECURITY_COMMENT = "\n".join([
    "<!-- socket-security-comment-actions -->",
    "<h2>Socket Security: Pull Request Alerts</h2>",
    "<table>",
    "<!-- start-socket-alert-npm/lodash@4.17.11 -->",
    "<tr><td><details><summary>npm/lodash@4.17.11 - Prototype Pollution</summary></details></td></tr>",
    "<!-- end-socket-alert-npm/lodash@4.17.11 -->",
    "<!-- start-socket-alert-npm/handlebars@4.0.11 -->",
    "<tr><td><details><summary>npm/handlebars@4.0.11 - Remote Code Execution</summary></details></td></tr>",
    "<!-- end-socket-alert-npm/handlebars@4.0.11 -->",
    "</table>",
    "[View full report](https://socket.dev/dashboard/org/acme/diff/abc?foo=bar)",
])
GITHUB_COMMENTS_PATH = "repos/acme/repo/issues/42/comments"
GITHUB_PERMISSION_PATH = "repos/acme/repo/collaborators/maintainer/permission"


def _comment(body: str, comment_id: int) -> Comment:
    return Comment(
        id=comment_id,
        body=body,
        body_list=body.split("\n"),
        reactions={"+1": 0},
        user={"login": "maintainer", "id": 7},
    )


def _run_comment_event(monkeypatch, raw_comments, *, permission="write", extra_args=()):
    argv = [
        "socketcli", "--api-token", "test", "--scm", "github",
        "--repo", "repo", "--branch", "feature", "--pr-number", "42",
        *extra_args,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    for key, value in {
        "GH_API_TOKEN": "test", "GITHUB_EVENT_NAME": "issue_comment",
        "EVENT_ACTION": "created", "GITHUB_REPOSITORY": "acme/repo",
        "DEFAULT_BRANCH": "false",
    }.items():
        monkeypatch.setenv(key, value)

    get_comments = Mock(return_value=[vars(comment) for comment in raw_comments.values()])

    def request(*, path, method="GET", **kwargs):
        assert method == "GET"
        if path == GITHUB_COMMENTS_PATH:
            return Mock(json=get_comments)
        assert path == GITHUB_PERMISSION_PATH
        return Mock(json=Mock(return_value={"permission": permission}))

    update_comment = Mock()
    monkeypatch.setattr(Github, "update_comment", update_comment)
    post_reaction = Mock()
    monkeypatch.setattr(Github, "post_reaction", post_reaction)
    monkeypatch.setattr(Github, "comment_reaction_exists", Mock(return_value=False))

    sdk = MagicMock()
    sdk.org.get.return_value = {"organizations": {"org-id": {"slug": "acme"}}}
    monkeypatch.setattr(socketcli, "build_socket_sdk", Mock(return_value=sdk))
    client = Mock()
    client.request.side_effect = request
    monkeypatch.setattr(socketcli, "CliClient", Mock(return_value=client))
    monkeypatch.setattr(socketcli, "StreamingLogs", lambda **kwargs: nullcontext(Mock()))
    monkeypatch.setattr(socketcli, "apply_git_context", lambda config: (False, None))
    scan = Mock()
    monkeypatch.setattr(socketcli.Core, "create_new_diff", scan)
    monkeypatch.setattr(socketcli.Core, "create_full_scan_with_report_url", scan)

    with pytest.raises(SystemExit) as result:
        socketcli.cli()

    scan.assert_not_called()
    return result.value.code, get_comments, update_comment, post_reaction, client


def _security_and(*bodies):
    raw = {1: _comment(SECURITY_COMMENT, 1)}
    for offset, body in enumerate(bodies, start=2):
        raw[offset] = _comment(body, offset)
    return raw


class TestCliCommentEvent:
    @pytest.mark.parametrize("body", [
        "LGTM, merging after CI",
        "",
        "Can we ignore this one? @SocketSecurity please look",
    ])
    def test_ordinary_comment_exits_0_and_leaves_security_comment(self, monkeypatch, body):
        code, get_comments, update_comment, post_reaction, client = _run_comment_event(
            monkeypatch, _security_and(body), extra_args=("--strict-blocking",),
        )

        assert code == 0
        get_comments.assert_called_once()
        assert [call.kwargs["path"] for call in client.request.call_args_list] == [
            GITHUB_COMMENTS_PATH,
        ]
        update_comment.assert_not_called()
        post_reaction.assert_not_called()
        client.post_telemetry_events.assert_not_called()

    def test_ordinary_comment_without_security_comment_exits_0(self, monkeypatch):
        code, _, update_comment, _, _ = _run_comment_event(
            monkeypatch, {5: _comment("ship it", 5)},
        )

        assert code == 0
        update_comment.assert_not_called()

    def test_ignore_command_removes_only_that_package(self, monkeypatch):
        code, _, update_comment, post_reaction, client = _run_comment_event(
            monkeypatch,
            _security_and("first ordinary comment", "@SocketSecurity ignore npm/lodash@4.17.11"),
        )

        assert code == 0
        update_comment.assert_called_once()
        body, comment_id = update_comment.call_args.args
        assert comment_id == "1"
        assert "start-socket-alert-npm/lodash@4.17.11" not in body
        assert "start-socket-alert-npm/handlebars@4.0.11" in body
        post_reaction.assert_called_once_with(3)
        events = client.post_telemetry_events.call_args.args[1]
        assert [e["artifact_input"] for e in events] == ["npm/lodash@4.17.11"]

    def test_ignore_all_clears_the_table(self, monkeypatch):
        code, _, update_comment, post_reaction, client = _run_comment_event(
            monkeypatch, _security_and("@SocketSecurity ignore-all"),
        )

        assert code == 0
        body = update_comment.call_args.args[0]
        assert "start-socket-alert" not in body
        assert "No dependency alerts to report" in body
        post_reaction.assert_called_once_with(2)
        events = client.post_telemetry_events.call_args.args[1]
        assert len(events) == 1 and events[0]["ignore_all"] is True

    @pytest.mark.parametrize("command", [
        "@SocketSecurity ignore npm/lodash@4.17.11", "@SocketSecurity ignore-all", "LGTM",
    ])
    def test_disable_ignore_skips_comment_processing(self, monkeypatch, command):
        code, get_comments, update_comment, post_reaction, client = _run_comment_event(
            monkeypatch, _security_and(command), extra_args=("--disable-ignore",),
        )

        assert code == 0
        get_comments.assert_not_called()
        client.request.assert_not_called()
        update_comment.assert_not_called()
        post_reaction.assert_not_called()
        client.post_telemetry_events.assert_not_called()

    def test_unauthorized_ignore_is_dropped_without_crashing(self, monkeypatch):
        code, _, update_comment, post_reaction, client = _run_comment_event(
            monkeypatch,
            _security_and("@SocketSecurity ignore npm/lodash@4.17.11"),
            permission="read",
            extra_args=("--strict-blocking",),
        )

        assert code == 0
        assert [call.kwargs["path"] for call in client.request.call_args_list] == [
            GITHUB_COMMENTS_PATH,
            GITHUB_PERMISSION_PATH,
        ]
        update_comment.assert_not_called()
        post_reaction.assert_not_called()
        client.post_telemetry_events.assert_not_called()

    @pytest.mark.parametrize("command", [
        "@SocketSecurity ignore",
        "@SocketSecurity ignore lodash",
        "@SocketSecurity ignore @4.17.11",
        "@SocketSecurity ignore npm/lodash@",
    ])
    def test_malformed_ignore_command_keeps_every_alert(self, monkeypatch, command):
        code, _, update_comment, _, _ = _run_comment_event(monkeypatch, _security_and(command))

        assert code == 0
        body = update_comment.call_args.args[0]
        assert "start-socket-alert-npm/lodash@4.17.11" in body
        assert "start-socket-alert-npm/handlebars@4.0.11" in body


class TestGetIgnoreOptions:
    def test_no_ignore_key(self):
        assert Comments.get_ignore_options({}) == (False, [])
        assert Comments.get_ignore_options({"security": _comment(SECURITY_COMMENT, 1)}) == (False, [])

    def test_process_security_comment_without_ignore_key_keeps_alerts(self):
        security = _comment(SECURITY_COMMENT, 1)
        body = Comments.process_security_comment(security, {"security": security})

        assert "start-socket-alert-npm/lodash@4.17.11" in body
        assert "start-socket-alert-npm/handlebars@4.0.11" in body


class TestAdapterRemoveCommentAlerts:
    def _github(self):
        gh = Github.__new__(Github)
        gh.update_comment = Mock()
        gh.handle_ignore_reactions = Mock()
        return gh

    def _gitlab(self):
        config = GitlabConfig(
            commit_sha="abc", api_url="https://gitlab.example.com/api/v4",
            project_dir=".", mr_source_branch="feature", mr_iid="7",
            mr_project_id=1, commit_message="", default_branch="main",
            project_name="repo", pipeline_source="merge_request_event",
            commit_author="dev", token="t", repository="repo", is_default_branch=False,
            headers={},
        )
        gl = Gitlab(client=MagicMock(), config=config)
        gl.update_comment = Mock()
        gl.handle_ignore_reactions = Mock()
        return gl

    @pytest.mark.parametrize("make", ["_github", "_gitlab"])
    def test_no_ignore_comments_leaves_security_comment(self, make):
        scm = getattr(self, make)()
        scm.remove_comment_alerts({"security": _comment(SECURITY_COMMENT, 1)})

        scm.update_comment.assert_not_called()
        scm.handle_ignore_reactions.assert_not_called()

    @pytest.mark.parametrize("make", ["_github", "_gitlab"])
    def test_ignore_comment_rewrites_security_comment(self, make):
        scm = getattr(self, make)()
        comments = Comments.check_for_socket_comments({
            1: _comment(SECURITY_COMMENT, 1),
            2: _comment("@SocketSecurity ignore npm/handlebars@4.0.11", 2),
        })
        scm.remove_comment_alerts(comments)

        body, comment_id = scm.update_comment.call_args.args
        assert comment_id == "1"
        assert "start-socket-alert-npm/handlebars@4.0.11" not in body
        assert "start-socket-alert-npm/lodash@4.17.11" in body
        scm.handle_ignore_reactions.assert_called_once_with(comments)
