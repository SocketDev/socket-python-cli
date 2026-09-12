"""Who is allowed to suppress an alert with @SocketSecurity ignore.

An ignore command silences a security finding, so it is honored only from someone
with write access to the repository. The gate lives in check_for_socket_comments,
so a rejected command never reaches the ignore parser, the alert filter, or the
ignore telemetry.
"""
from types import SimpleNamespace

import pytest

from socketsecurity.core.classes import Comment
from socketsecurity.core.scm.github import Github
from socketsecurity.core.scm.gitlab import Gitlab
from socketsecurity.core.scm_comments import Comments


def _comment(body="@SocketSecurity ignore npm/lodash@4.17.21", **fields):
    return Comment(id=1, body=body, body_list=body.split("\n"), **fields)


# --- GitHub: effective repository permission is looked up and cached ---------


def _github(permission="write", raises=None, policy="enforce", response=None):
    github = Github.__new__(Github)
    github.config = SimpleNamespace(
        owner="o", repository="r", headers={}, api_url="https://api.github.com"
    )
    github.ignore_authorization = policy
    github._ignore_permission_cache = {}
    calls = []

    def fake_request(**kwargs):
        calls.append(kwargs["path"])
        if raises:
            raise raises
        payload = response if response is not None else {"permission": permission}
        return SimpleNamespace(json=lambda: payload)

    github.client = SimpleNamespace(request=fake_request)
    github.calls = calls
    return github


@pytest.mark.parametrize("permission", ["write", "maintain", "admin"])
def test_github_write_access_may_ignore(permission):
    github = _github(permission)
    comment = _comment(user={"login": "maintainer"}, author_association="NONE")

    assert github.is_ignore_authorized(comment) is True


@pytest.mark.parametrize("permission", ["read", "triage", "none"])
def test_github_without_write_access_may_not_ignore(permission):
    github = _github(permission)
    comment = _comment(user={"login": "reader"}, author_association="MEMBER")

    assert github.is_ignore_authorized(comment) is False


def test_github_permission_is_fetched_once_per_commenter():
    github = _github("write")
    comment = _comment(user={"login": "maintainer"})

    github.is_ignore_authorized(comment)
    github.is_ignore_authorized(comment)

    assert github.calls == ["repos/o/r/collaborators/maintainer/permission"]


def test_github_unreadable_permission_honors_the_command_with_a_warning(caplog):
    github = _github(raises=Exception("403 Forbidden"))

    with caplog.at_level("WARNING", logger="socketcli"):
        allowed = github.is_ignore_authorized(
            _comment(user={"login": "maintainer"})
        )

    assert allowed is True
    assert "without verifying write access" in caplog.text


def test_github_strict_rejects_when_permission_cannot_be_read(caplog):
    github = _github(raises=Exception("403 Forbidden"), policy="strict")

    with caplog.at_level("WARNING", logger="socketcli"):
        allowed = github.is_ignore_authorized(
            _comment(user={"login": "maintainer"})
        )

    assert allowed is False
    assert "strict" in caplog.text


def test_github_unexpected_permission_response_is_indeterminate(caplog):
    github = _github(response={"role_name": "custom-role"}, policy="strict")

    with caplog.at_level("WARNING", logger="socketcli"):
        allowed = github.is_ignore_authorized(
            _comment(user={"login": "maintainer"})
        )

    assert allowed is False
    assert "Unexpected GitHub repository permission response" in caplog.text


def test_unauthorized_command_never_reaches_the_ignore_bucket():
    github = _github("read")
    outsider = _comment(user={"login": "outsider"}, author_association="MEMBER")

    bucketed = Comments.check_for_socket_comments(
        {outsider.id: outsider}, github.is_ignore_authorized
    )

    assert "ignore" not in bucketed
    # ...so the alert it named survives.
    alert = SimpleNamespace(
        pkg_name="lodash", pkg_version="4.17.21", pkg_type="npm", type="malware"
    )
    assert Comments.remove_alerts(bucketed, [alert]) == [alert]


def test_ignore_all_from_an_outsider_is_rejected_too():
    """ignore-all is the more powerful command; it goes through the same gate."""
    github = _github("read")
    outsider = _comment(
        body="@SocketSecurity ignore-all",
        user={"login": "outsider"},
        author_association="MEMBER",
    )

    assert "ignore" not in Comments.check_for_socket_comments(
        {outsider.id: outsider}, github.is_ignore_authorized
    )


# --- GitLab: notes carry no permission field, so membership is looked up -----


def _gitlab(members_pages=None, raises=None, policy="enforce"):
    gitlab = Gitlab.__new__(Gitlab)
    gitlab.config = SimpleNamespace(mr_project_id="42", headers={}, api_url="https://gl/api/v4")
    gitlab.ignore_authorization = policy
    gitlab._member_access = None
    gitlab._member_lookup_attempted = False

    calls = []

    def fake_request(**kwargs):
        calls.append(kwargs["path"])
        if raises:
            raise raises
        return SimpleNamespace(json=lambda: members_pages.pop(0))

    gitlab._request_with_fallback = fake_request
    gitlab.calls = calls
    return gitlab


@pytest.mark.parametrize("access_level,expected", [(50, True), (40, True), (30, True), (20, False), (10, False)])
def test_gitlab_requires_developer_access(access_level, expected):
    gitlab = _gitlab([[{"id": 7, "access_level": access_level}]])
    comment = _comment(author={"id": 7, "username": "someone"})

    assert gitlab.is_ignore_authorized(comment) is expected


def test_gitlab_non_member_may_not_ignore():
    """The outsider case: a 200 listing that simply does not contain them."""
    gitlab = _gitlab([[{"id": 7, "access_level": 40}]])
    comment = _comment(author={"id": 999, "username": "outsider"})

    assert gitlab.is_ignore_authorized(comment) is False


def test_gitlab_membership_is_fetched_once_per_run():
    gitlab = _gitlab([[{"id": 7, "access_level": 40}]])

    gitlab.is_ignore_authorized(_comment(author={"id": 7}))
    gitlab.is_ignore_authorized(_comment(author={"id": 8}))

    assert len(gitlab.calls) == 1


def test_gitlab_paginates_until_a_short_page():
    first = [{"id": i, "access_level": 30} for i in range(Gitlab.MEMBER_PAGE_SIZE)]
    gitlab = _gitlab([first, [{"id": 999, "access_level": 40}]])

    assert gitlab.is_ignore_authorized(_comment(author={"id": 999})) is True
    assert len(gitlab.calls) == 2


def test_gitlab_unreadable_membership_honors_the_command_with_a_warning(caplog):
    """A CI_JOB_TOKEN usually cannot read members; that must not break pipelines."""
    gitlab = _gitlab(raises=Exception("403 Forbidden"))

    with caplog.at_level("WARNING", logger="socketcli"):
        allowed = gitlab.is_ignore_authorized(_comment(author={"id": 7, "username": "dev"}))

    assert allowed is True
    assert "without verifying write access" in caplog.text


def test_gitlab_oversized_membership_is_undetermined():
    full = [{"id": i, "access_level": 30} for i in range(Gitlab.MEMBER_PAGE_SIZE)]
    gitlab = _gitlab([list(full) for _ in range(Gitlab.MEMBER_PAGE_LIMIT)])

    # Undetermined falls back to honoring the command, same as an API failure.
    assert gitlab.is_ignore_authorized(_comment(author={"id": 999})) is True
    assert len(gitlab.calls) == Gitlab.MEMBER_PAGE_LIMIT


# --- --ignore-authorization ---------------------------------------------------


def test_strict_rejects_when_membership_cannot_be_read(caplog):
    """strict closes the gap enforce leaves open, at the cost of breaking a
    pipeline whose token cannot read members."""
    gitlab = _gitlab(raises=Exception("403 Forbidden"), policy="strict")

    with caplog.at_level("WARNING", logger="socketcli"):
        allowed = gitlab.is_ignore_authorized(_comment(author={"id": 7, "username": "dev"}))

    assert allowed is False
    assert "strict" in caplog.text


def test_strict_still_honors_a_verified_member():
    gitlab = _gitlab([[{"id": 7, "access_level": 40}]], policy="strict")

    assert gitlab.is_ignore_authorized(_comment(author={"id": 7})) is True


def test_off_skips_the_gate_entirely():
    """off restores the prior behavior: no predicate reaches the bucketing, so
    nothing is filtered and no rejection is logged."""
    github = Github.__new__(Github)
    github.ignore_authorization = "off"
    github.config = SimpleNamespace(owner="o", repository="r", pr_number="1",
                                    headers={}, api_url="https://api.github.com")
    github.client = SimpleNamespace(request=lambda **kw: SimpleNamespace(
        json=lambda: [{"id": 1, "body": "@SocketSecurity ignore npm/lodash@4.17.21",
                       "author_association": "NONE", "user": {"login": "outsider"}}],
        text=""))

    bucketed = github.get_comments_for_pr()

    assert len(bucketed.get("ignore", [])) == 1


def test_enforce_is_the_default_policy():
    from socketsecurity.config import CliConfig

    assert CliConfig.from_args(["--api-token", "t"]).ignore_authorization == "enforce"
