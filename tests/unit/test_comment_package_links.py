"""Package links and size limits in security comments rendered from diff artifacts."""

import re
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from socketsecurity.core import Core
from socketsecurity.core.classes import Comment, Diff, Package
from socketsecurity.core.messages import Messages
from socketsecurity.core.scm_comments import Comments


@dataclass
class _FakeConfig:
    disable_ignore: bool = False
    scm: str = "github"
    strict_blocking: bool = True


ECOSYSTEMS = {
    "npm": (
        dict(type="npm", name="handlebars", version="4.0.11"),
        "https://socket.dev/npm/package/handlebars/overview/4.0.11",
    ),
    "npm-scoped": (
        dict(type="npm", namespace="@babel", name="traverse", version="7.22.5"),
        "https://socket.dev/npm/package/@babel/traverse/overview/7.22.5",
    ),
    "pypi": (
        dict(type="pypi", name="django", version="2.2"),
        "https://socket.dev/pypi/package/django/overview/2.2",
    ),
    "maven": (
        dict(type="maven", namespace="org.apache.logging.log4j", name="log4j-core", version="2.14.1"),
        "https://socket.dev/maven/package/org.apache.logging.log4j/log4j-core/overview/2.14.1",
    ),
    "golang": (
        dict(type="golang", namespace="github.com/gin-gonic", name="gin", version="v1.6.0"),
        "https://socket.dev/golang/package/github.com/gin-gonic/gin/overview/v1.6.0",
    ),
    "nuget": (
        dict(type="nuget", name="Newtonsoft.Json", version="12.0.1"),
        "https://socket.dev/nuget/package/Newtonsoft.Json/overview/12.0.1",
    ),
    "gem": (
        dict(type="gem", name="rails", version="5.2.0"),
        "https://socket.dev/gem/package/rails/overview/5.2.0",
    ),
    "cargo": (
        dict(type="cargo", name="smallvec", version="0.6.9"),
        "https://socket.dev/cargo/package/smallvec/overview/0.6.9",
    ),
}

CVE_ALERT = {"type": "criticalCVE", "key": "cve-key", "severity": "critical", "action": "error"}
LICENSE_ALERT = {"type": "licenseSpdxDisj", "key": "license-key", "severity": "low", "action": "error"}


def _issues(artifact: dict, alert: dict) -> list:
    package = Package.from_diff_artifact({
        "id": f"{artifact['type']}-{artifact['name']}",
        "score": {},
        "topLevelAncestors": [],
        "direct": True,
        "manifestFiles": [{"file": "manifest"}],
        "alerts": [alert],
        **artifact,
    })
    package = Core.update_package_values(package)
    core = Core.__new__(Core)
    core.config = SimpleNamespace(all_issues=SimpleNamespace())
    collection = core.add_package_alerts_to_collection(package, {}, {package.id: package})
    return collection[alert["key"]]


def _this_package_hrefs(body: str) -> list:
    return re.findall(r'<a href="([^"]*)">This package</a>', body)


def _diff(alerts: list) -> Diff:
    diff = Diff()
    diff.id = "scan"
    diff.diff_url = "https://socket.dev/dashboard/org/acme/diff/abc"
    diff.new_alerts = alerts
    diff.unchanged_alerts = []
    return diff


@pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
def test_alert_row_links_the_package_page(ecosystem):
    artifact, expected = ECOSYSTEMS[ecosystem]
    alerts = _issues(artifact, CVE_ALERT)

    body = Messages.security_comment_template(_diff(alerts), _FakeConfig())

    assert _this_package_hrefs(body) == [expected]
    assert body.count(f'href="{expected}"') == 1


@pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
def test_license_row_links_the_package_page(ecosystem):
    artifact, expected = ECOSYSTEMS[ecosystem]
    alerts = _issues(artifact, LICENSE_ALERT)

    body = Messages.security_comment_template(_diff(alerts), _FakeConfig())

    assert _this_package_hrefs(body) == [expected]


@pytest.mark.parametrize("alert", [CVE_ALERT, LICENSE_ALERT], ids=["alert", "license"])
def test_existing_alerts_table_links_the_package_page(alert):
    artifact, expected = ECOSYSTEMS["npm-scoped"]
    diff = _diff([])
    diff.unchanged_alerts = _issues(artifact, alert)

    body = Messages.security_comment_template(diff, _FakeConfig())

    assert _this_package_hrefs(body) == [expected]


@pytest.mark.parametrize("section", ["new_alerts", "unchanged_alerts"])
@pytest.mark.parametrize("alert", [CVE_ALERT, LICENSE_ALERT], ids=["security", "license"])
def test_rows_keep_package_namespaces_distinct(section, alert):
    issues = []
    for scope in ("@alpha", "@beta"):
        artifact = dict(type="npm", namespace=scope, name="widgets", version="1.0.0")
        issues += _issues(artifact, alert)
    diff = _diff([])
    setattr(diff, section, issues)

    body = Messages.security_comment_template(diff, _FakeConfig())

    assert _this_package_hrefs(body) == [
        "https://socket.dev/npm/package/@alpha/widgets/overview/1.0.0",
        "https://socket.dev/npm/package/@beta/widgets/overview/1.0.0",
    ]
    assert "<summary>@alpha/widgets@1.0.0" in body
    assert "<summary>@beta/widgets@1.0.0" in body
    command = "@SocketSecurity ignore npm/@alpha/widgets@1.0.0"
    assert f"<code>{command}</code>" in body
    comment = Comment(body_list=body.splitlines())
    comments = {"ignore": [Comment(body_list=[command])]}
    assert Comments.remove_alerts(comments, issues) == [issues[1]]
    updated = Comments.process_security_comment(comment, comments)
    assert _this_package_hrefs(updated) == _this_package_hrefs(body)[1:]

    legacy = {"ignore": [Comment(body_list=["@SocketSecurity ignore npm/widgets@1.0.0"])]}
    assert Comments.remove_alerts(legacy, issues) == []
    assert "No dependency alerts to report" in Comments.process_security_comment(comment, legacy)


@pytest.mark.parametrize("with_existing", [False, True])
def test_large_comments_keep_omission_counts_and_the_full_report(with_existing):
    new_issues = [
        _issues(dict(type="npm", name=f"widget-{i}", version="1.0.0"), CVE_ALERT)[0]
        for i in range(60)
    ]
    for issue in new_issues:
        issue.description = "説明" * 200
    diff = _diff(new_issues)
    if with_existing:
        artifact = dict(type="npm", name="existing-widget", version="1.0.0")
        diff.unchanged_alerts = _issues(artifact, CVE_ALERT)
        diff.unchanged_alerts[0].description = "説明" * 500

    body = Messages.security_comment_template(diff, _FakeConfig())

    visible = re.findall(r"<!-- start-socket-alert-(widget-\d+@1.0.0) -->", body)
    assert 0 < len(visible) < len(new_issues)
    assert f"{len(new_issues) - len(visible)} more new alert(s) are not shown" in body
    assert len(body.encode()) <= Messages.SECURITY_COMMENT_SIZE_BUDGET
    assert body.count("</table>") == (2 if with_existing else 1)
    if with_existing:
        assert "1 more existing alert(s) are not shown" in body
        assert "Existing alerts (1)" in body
    report_link = f"[View full report]({diff.diff_url}?action=error%2Cwarn)"
    assert report_link in body
    assert len(diff.new_alerts) == 60
    assert len(diff.unchanged_alerts) == int(with_existing)

    comment = Comment(body_list=body.splitlines())
    individual_ignores = [
        Comment(body_list=[f"@SocketSecurity ignore npm/{coordinate}"])
        for coordinate in visible
    ]
    updated = Comments.process_security_comment(comment, {"ignore": individual_ignores})
    assert "more new alert(s) are not shown" in updated
    assert "No dependency alerts to report" not in updated
    assert report_link in updated

    ignore_all = Comment(body_list=["@SocketSecurity ignore-all"])
    cleared = Comments.process_security_comment(comment, {"ignore": [ignore_all]})
    assert "No dependency alerts to report" in cleared
    assert "more new alert(s)" not in cleared


@pytest.mark.parametrize("scm", ["github", "gitlab"])
def test_no_relative_package_links_on_either_scm(scm):
    alerts = [
        alert
        for artifact, _ in ECOSYSTEMS.values()
        for alert in _issues(artifact, CVE_ALERT) + _issues(artifact, LICENSE_ALERT)
    ]

    body = Messages.security_comment_template(_diff(alerts), _FakeConfig(scm=scm))

    hrefs = _this_package_hrefs(body)
    assert len(hrefs) == 2 * len(ECOSYSTEMS)
    assert all(href.startswith("https://socket.dev/") for href in hrefs)


def test_package_url_is_attribute_escaped():
    artifact = dict(type="npm", name='evil"><script>', version="1.0.0")
    alerts = _issues(artifact, CVE_ALERT)

    body = Messages.security_comment_template(_diff(alerts), _FakeConfig())

    assert _this_package_hrefs(body) == [
        "https://socket.dev/npm/package/evil&quot;&gt;&lt;script&gt;/overview/1.0.0"
    ]
