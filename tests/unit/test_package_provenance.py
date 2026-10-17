import copy
import json

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.classes import Diff, Issue, Package
from socketsecurity.core.messages import Messages
from socketsecurity.core.report_output import build_socket_json_report


def _package(
    package_id: str,
    *,
    name: str = "widget",
    version: str = "1.0.0",
    ecosystem: str = "npm",
    namespace: str | None = None,
    direct: bool = False,
    ancestors: list[str] | None = None,
    manifests: list[dict[str, str]] | None = None,
    purl: str = "",
) -> Package:
    package = Package(
        type=ecosystem,
        namespace=namespace,
        name=name,
        version=version,
        id=package_id,
        score={},
        alerts=[],
        direct=direct,
        topLevelAncestors=ancestors,
        manifestFiles=manifests,
        purl=purl,
    )
    return package


def _issue(introduced_by: list[tuple[str, str]]) -> Issue:
    return Issue(
        pkg_type="npm",
        pkg_name="leaf",
        pkg_version="1.0.0",
        category="supplyChainRisk",
        type="envVars",
        severity="low",
        pkg_id="npm/leaf@1.0.0",
        props={},
        key="fixture-alert",
        error=False,
        warn=True,
        ignore=False,
        monitor=False,
        description="Fixture alert",
        title="Fixture alert",
        emoji="!",
        next_step_title="Review package",
        suggestion="",
        introduced_by=introduced_by,
        purl="pkg:npm/leaf@1.0.0",
        url="https://socket.dev/npm/package/leaf/alerts/1.0.0",
    )


def test_source_data_preserves_scopes_and_maven_groups_and_consumers():
    first = _package("first", namespace="@one", manifests=[{"file": "package.json"}])
    second = _package("second", namespace="@two", manifests=[{"file": "package.json"}])
    maven = _package(
        "maven",
        ecosystem="maven",
        namespace="com.one",
        manifests=[{"file": "pom.xml"}],
    )
    child = _package("child", ancestors=["first", "second", "maven"])
    packages = {package.id: package for package in (first, second, maven, child)}
    before = copy.deepcopy(packages)

    sources = Core.get_source_data(child, packages)

    assert sources == [
        ("npm/@one/widget@1.0.0", "package.json"),
        ("npm/@two/widget@1.0.0", "package.json"),
        ("maven/com.one/widget@1.0.0", "pom.xml"),
    ]
    assert packages == before
    issue = _issue(sources[:2])
    _, raw = Messages.create_sources(issue, "raw")
    _, console = Messages.create_sources(issue, "console")
    _, markdown = Messages.create_sources(issue, "md")
    assert raw == "npm/@one/widget@1.0.0;npm/@two/widget@1.0.0"
    assert console == raw
    assert "npm/@one/widget@1.0.0" in markdown
    assert "npm/@two/widget@1.0.0" in markdown

    report = build_socket_json_report(
        Diff(new_alerts=[issue]), CliConfig(api_token="", repo="fixture")
    )
    serialized = json.loads(json.dumps(report))
    assert serialized["new_alerts"][0]["introduced_by"] == [
        ["npm/@one/widget@1.0.0", "package.json"],
        ["npm/@two/widget@1.0.0", "package.json"],
    ]
    assert len(serialized) == 18


def test_source_data_preserves_unscoped_direct_missing_and_order_behavior():
    unscoped = _package(
        "root",
        ecosystem="pypi",
        namespace=None,
        manifests=[{"file": "requirements.in"}, {"file": "requirements.txt"}],
    )
    empty = _package(
        "empty",
        ecosystem="pypi",
        namespace="",
        manifests=[{"file": "pyproject.toml"}],
    )
    direct = _package(
        "direct",
        direct=True,
        manifests=[{"file": "one.json"}, {"file": "two.json"}],
    )
    no_manifest = _package("no-manifest", manifests=[])
    child = _package(
        "child", ancestors=["root", "empty", "missing", "root", "no-manifest"]
    )
    packages = {item.id: item for item in (unscoped, empty, direct, no_manifest, child)}

    assert Core.get_source_data(child, packages) == [
        ("pypi/widget@1.0.0", "requirements.in;requirements.txt"),
        ("pypi/widget@1.0.0", "pyproject.toml"),
        ("pypi/widget@1.0.0", "requirements.in;requirements.txt"),
    ]
    assert Core.get_source_data(direct, packages) == [("direct", "one.json;two.json")]
    assert Core.get_source_data(_package("orphan", ancestors=[]), packages) == []
    assert (
        Core.get_source_data(_package("missing", ancestors=["absent"]), packages) == []
    )


def test_source_data_uses_structured_identity_without_mutating_purls_or_traversing():
    artifact = {
        "id": "socket",
        "type": "npm",
        "namespace": "@one",
        "name": "widget",
        "version": "1.0.0",
        "score": {},
        "alerts": [],
        "topLevelAncestors": [],
        "manifestFiles": [{"file": "package.json"}],
    }
    socket_package = Package.from_socket_artifact(artifact)
    comparison_package = _package(
        "comparison",
        namespace="@one",
        purl="@one/widget@1.0.0",
        manifests=[{"file": "package.json"}],
    )
    Core.update_package_values(comparison_package)
    child = _package("child", ancestors=["socket", "comparison", "socket", "child"])
    socket_package.topLevelAncestors = ["comparison"]
    comparison_package.topLevelAncestors = ["socket"]
    packages = {item.id: item for item in (socket_package, comparison_package, child)}
    original_purls = (socket_package.purl, comparison_package.purl)
    original = copy.deepcopy(packages)

    assert Core.get_source_data(child, packages) == [
        ("npm/@one/widget@1.0.0", "package.json"),
        ("npm/@one/widget@1.0.0", "package.json"),
        ("npm/@one/widget@1.0.0", "package.json"),
    ]
    assert Core.get_source_data(socket_package, packages) == [
        ("npm/@one/widget@1.0.0", "package.json")
    ]
    assert socket_package.purl == original_purls[0]
    assert comparison_package.purl == original_purls[1]
    assert packages == original
