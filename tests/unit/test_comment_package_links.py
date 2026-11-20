"""The "This package" link in PR/MR security comments must be an absolute URL.

It used to be the bare package coordinate (``handlebars@4.0.11``), which GitHub
and GitLab resolve as a relative link to a page that does not exist. Each case
here goes from a diff artifact, as the API returns it, through the same Package
and Issue construction a real run uses, to the rendered comment.
"""

import re
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from socketsecurity.core import Core
from socketsecurity.core.classes import Diff, Package
from socketsecurity.core.messages import Messages


@dataclass
class _FakeConfig:
    disable_ignore: bool = False
    scm: str = "github"
    strict_blocking: bool = True


# (artifact fields, expected package page URL)
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
    """Build Issues the way a scan does: diff artifact -> Package -> Issue."""
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


@pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
def test_license_row_links_the_package_page(ecosystem):
    artifact, expected = ECOSYSTEMS[ecosystem]
    alerts = _issues(artifact, LICENSE_ALERT)

    body = Messages.security_comment_template(_diff(alerts), _FakeConfig())

    assert _this_package_hrefs(body) == [expected]


@pytest.mark.parametrize("alert", [CVE_ALERT, LICENSE_ALERT], ids=["alert", "license"])
def test_existing_alerts_table_links_the_package_page(alert):
    """The --strict-blocking existing-alerts table reuses the same row templates."""
    artifact, expected = ECOSYSTEMS["npm-scoped"]
    diff = _diff([])
    diff.unchanged_alerts = _issues(artifact, alert)

    body = Messages.security_comment_template(diff, _FakeConfig())

    assert _this_package_hrefs(body) == [expected]


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
