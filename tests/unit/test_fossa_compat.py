from socketsecurity.config import CliConfig
from socketsecurity.core.classes import Diff, Issue, Package
from socketsecurity.fossa_compat import (
    build_fossa_attribution_payload,
    build_fossa_report_payload,
)

EXPECTED_TOP_LEVEL_KEYS = ["project", "vulnerability", "licensing", "quality"]
EXPECTED_PROJECT_KEYS = ["branch", "id", "project", "projectId", "revision", "url"]
EXPECTED_VULNERABILITY_KEYS = [
    "affectedVersionRanges",
    "containerLayers",
    "cpes",
    "createdAt",
    "customRiskScore",
    "cve",
    "cveStatus",
    "cwes",
    "cvss",
    "cvssVector",
    "depths",
    "details",
    "epss",
    "exploitability",
    "id",
    "metrics",
    "patchedVersionRanges",
    "projects",
    "published",
    "references",
    "remediation",
    "severity",
    "source",
    "statuses",
    "title",
    "type",
    "url",
    "vulnId",
]
EXPECTED_SOURCE_KEYS = ["id", "name", "packageManager", "url", "version"]
EXPECTED_DEPTH_KEYS = ["deep", "direct"]
EXPECTED_STATUS_KEYS = ["active", "ignored"]
EXPECTED_REMEDIATION_KEYS = [
    "completeFix",
    "completeFixDistance",
    "partialFix",
    "partialFixDistance",
]
EXPECTED_EPSS_KEYS = ["percentile", "score"]


def test_fossa_report_payload_uses_expected_top_level_shape():
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    diff = Diff(id="scan-123", report_url="https://socket.dev/report/123")

    payload = build_fossa_report_payload(diff, config)

    assert list(payload.keys()) == EXPECTED_TOP_LEVEL_KEYS
    assert sorted(payload["project"].keys()) == sorted(EXPECTED_PROJECT_KEYS)
    assert payload["vulnerability"] == []
    assert payload["licensing"] == []
    assert payload["quality"] == []


def test_fossa_report_payload_vulnerability_shape_is_stable():
    config = CliConfig.from_args([
        "--api-token", "test",
        "--legal-format", "fossa",
        "--repo", "owner/repo",
        "--branch", "refs/heads/main",
    ])
    diff = Diff(id="scan-123", report_url="https://socket.dev/report/123")
    diff.packages = {
        "pkg-1": Package(
            id="pkg-1",
            name="requests",
            version="2.31.0",
            type="pypi",
            score={},
            alerts=[],
            direct=True,
            url="https://requests.readthedocs.io/",
            license="Apache-2.0",
            purl="pkg:pypi/requests@2.31.0",
        )
    }
    diff.new_alerts = [
        Issue(
            title="Insufficiently Protected Credentials",
            severity="medium",
            description="Requests may leak credentials for crafted URLs.",
            error=True,
            key="GHSA-9hjg-9r4m-mvj7",
            type="vulnerability",
            pkg_type="pypi",
            pkg_name="requests",
            pkg_version="2.31.0",
            pkg_id="pkg-1",
            purl="pkg:pypi/requests@2.31.0",
            url="https://socket.dev/pypi/package/requests/alerts/2.31.0",
            props={
                "id": 11088938,
                "createdAt": "2025-10-08T10:41:05.933Z",
                "ghsaId": "GHSA-9hjg-9r4m-mvj7",
                "cveId": "CVE-2024-47081",
                "cvssScore": 5.3,
                "fixedVersion": "2.32.4",
                "partialFixDistance": "MINOR",
                "completeFixDistance": "MINOR",
                "attackVector": "Network",
                "attackComplexity": "High",
                "privilegesRequired": "None",
                "userInteraction": "Required",
                "scope": "Unchanged",
                "confidentialityImpact": "High",
                "integrityImpact": "None",
                "availabilityImpact": "None",
                "cveStatus": "COMPLETED",
                "cwes": ["CWE-522"],
                "published": "2025-06-09T19:06:08Z",
                "affectedVersionRanges": ["<2.32.4"],
                "patchedVersionRanges": ["2.32.4"],
                "references": ["https://github.com/advisories/GHSA-9hjg-9r4m-mvj7"],
                "cvssVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                "exploitability": "UNKNOWN",
                "epssScore": 0.00154,
                "epssPercentile": 0.35957,
                "cpes": [],
            },
        )
    ]

    payload = build_fossa_report_payload(diff, config)
    generated_vulnerability = payload["vulnerability"][0]

    assert sorted(generated_vulnerability.keys()) == sorted(EXPECTED_VULNERABILITY_KEYS)
    assert sorted(generated_vulnerability["source"].keys()) == sorted(EXPECTED_SOURCE_KEYS)
    assert sorted(generated_vulnerability["depths"].keys()) == sorted(EXPECTED_DEPTH_KEYS)
    assert sorted(generated_vulnerability["statuses"].keys()) == sorted(EXPECTED_STATUS_KEYS)
    assert sorted(generated_vulnerability["remediation"].keys()) == sorted(EXPECTED_REMEDIATION_KEYS)
    assert sorted(generated_vulnerability["epss"].keys()) == sorted(EXPECTED_EPSS_KEYS)
    assert generated_vulnerability["source"]["packageManager"] == "pip"
    assert generated_vulnerability["vulnId"] == "GHSA-9hjg-9r4m-mvj7"
    assert generated_vulnerability["cve"] == "CVE-2024-47081"


def test_project_metadata_uses_dollar_revision_separator():
    """The composed FOSSA `project.id` is `<projectLocator>$<revision>`."""
    from socketsecurity.fossa_compat import _build_project_metadata
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa", "--repo", "acme/widgets", "--branch", "refs/heads/main"])
    diff = Diff(id="scan-abc123", report_url="https://socket.dev/x")
    project = _build_project_metadata(diff, config)
    assert project == {
        "branch": "refs/heads/main",
        "id": "acme/widgets$scan-abc123",
        "project": "acme/widgets",
        "projectId": "acme/widgets",
        "revision": "scan-abc123",
        "url": "https://socket.dev/x",
    }


def test_project_metadata_fallbacks_when_missing_fields():
    """Falls back to literal placeholders when config/diff are sparse."""
    from socketsecurity.fossa_compat import _build_project_metadata
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    # Force absent repo/branch:
    config.repo = None
    config.branch = None
    diff = Diff()
    project = _build_project_metadata(diff, config)
    assert project["branch"] == "socket-default-branch"
    assert project["project"] == "socket-default-repo"
    assert project["revision"] == "unknown-revision"
    assert project["id"] == "socket-default-repo$unknown-revision"
    assert project["url"] is None


def test_dependency_entry_full_shape():
    """Per-dependency dict has the exact 14-key FOSSA attribution shape."""
    from socketsecurity.fossa_compat import _build_dependency_entry
    package = Package(
        type="pypi",
        name="requests",
        version="2.31.0",
        id="pip+requests$2.31.0",
        score={},
        alerts=[],
        direct=True,
        author=["Kenneth Reitz <me@kennethreitz.com>"],
        license="Apache-2.0",
        licenseAttrib=[{"attribText": "Apache License 2.0\n\nCopyright 2023 Kenneth Reitz",
                         "attribData": [{"spdxExpr": "Apache-2.0"}]}],
    )
    entry = _build_dependency_entry(package, dependency_paths=["requests"])
    assert set(entry.keys()) == {
        "authors", "dependencyPaths", "description", "downloadUrl", "hash",
        "isGolang", "licenses", "notes", "otherLicenses", "package",
        "projectUrl", "source", "title", "version",
    }
    assert entry["authors"] == ["Kenneth Reitz <me@kennethreitz.com>"]
    assert entry["dependencyPaths"] == ["requests"]
    assert entry["description"] == ""
    assert entry["downloadUrl"] == ""
    assert entry["hash"] is None
    assert entry["isGolang"] is None
    assert entry["licenses"] == [{
        "attribution": "Apache License 2.0\n\nCopyright 2023 Kenneth Reitz",
        "name": "Apache-2.0",
    }]
    assert entry["notes"] == []
    assert entry["otherLicenses"] == []
    assert entry["package"] == "requests"
    assert entry["projectUrl"] == ""
    assert entry["source"] == "pip"
    assert entry["title"] == "requests"
    assert entry["version"] == "2.31.0"


def test_dependency_entry_falls_back_to_declared_license_when_no_attrib():
    """When licenseAttrib is empty, `licenses[]` falls back to a single name-only entry from Package.license."""
    from socketsecurity.fossa_compat import _build_dependency_entry
    package = Package(
        type="pypi", name="x", version="1.0", id="pip+x$1.0",
        score={}, alerts=[], license="MIT",
    )
    entry = _build_dependency_entry(package, dependency_paths=["x"])
    assert entry["licenses"] == [{"attribution": "", "name": "MIT"}]


def test_dependency_entry_unlicensed_package_emits_empty_licenses():
    from socketsecurity.fossa_compat import _build_dependency_entry
    package = Package(
        type="pypi", name="x", version="1.0", id="pip+x$1.0",
        score={}, alerts=[], license=None,
    )
    entry = _build_dependency_entry(package, dependency_paths=["x"])
    assert entry["licenses"] == []


def test_analyze_payload_top_level_keys_exactly_four():
    """The composed FOSSA analyze artifact has exactly project/vulnerability/licensing/quality."""
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    diff = Diff()  # empty alerts
    payload = build_fossa_report_payload(diff, config)
    assert set(payload.keys()) == {"project", "vulnerability", "licensing", "quality"}
    assert "risk" not in payload


def test_analyze_payload_empty_diff_yields_empty_arrays():
    """An empty diff still emits all 4 keys with `[]` arrays."""
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    payload = build_fossa_report_payload(Diff(), config)
    assert payload["vulnerability"] == []
    assert payload["licensing"] == []
    assert payload["quality"] == []


def test_vulnerability_gap_fields_emit_known_defaults():
    """Fields with no Socket data source emit documented null/empty defaults."""
    from socketsecurity.fossa_compat import _build_vulnerability_entry
    issue = Issue(
        type="criticalCVE",
        severity="high",
        key="x",
        pkg_type="pypi",
        pkg_name="x",
        pkg_version="1.0",
        props={},
    )
    package = Package(
        type="pypi",
        name="x",
        version="1.0",
        id="pip+x$1.0",
        score={},
        alerts=[],
        direct=True,
    )
    project = {"branch": "m", "id": "a$x", "project": "a", "projectId": "a", "revision": "x", "url": "u"}
    entry = _build_vulnerability_entry(issue, package, project, index=1)
    # Documented gap fields:
    assert entry["epss"] == {"score": None, "percentile": None}
    assert entry["cvssVector"] is None
    assert entry["exploitability"] is None
    assert entry["cveStatus"] is None
    assert entry["published"] is None
    assert entry["containerLayers"] == {"base": 0, "other": 0}
    assert entry["remediation"]["partialFixDistance"] is None
    assert entry["remediation"]["completeFixDistance"] is None
    assert "customRiskScore" in entry
    assert entry["customRiskScore"] is None
    proj_entry = entry["projects"][0]
    assert proj_entry["scannedAt"] is None
    assert proj_entry["analyzedAt"] is None
    assert proj_entry["firstFoundAt"] is None


def test_attribution_payload_top_level_is_5_keys():
    """fossa-sbom.json has exactly the 5 keys from `fossa report --json attribution`."""
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    payload = build_fossa_attribution_payload(Diff(), config)
    assert set(payload.keys()) == {
        "copyrightsByLicense",
        "deepDependencies",
        "directDependencies",
        "licenses",
        "project",
    }


def test_attribution_project_has_only_name_and_revision():
    """SBOM `project` is the 2-key subset, not the 6-key analyze project."""
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa", "--repo", "acme/widgets"])
    diff = Diff(id="rev-x")
    payload = build_fossa_attribution_payload(diff, config)
    assert payload["project"] == {"name": "acme/widgets", "revision": "rev-x"}


def test_attribution_empty_diff_yields_empty_collections():
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    payload = build_fossa_attribution_payload(Diff(), config)
    assert payload["copyrightsByLicense"] == {}
    assert payload["licenses"] == {}
    assert payload["directDependencies"] == []
    assert payload["deepDependencies"] == []


def test_attribution_partitions_direct_vs_deep():
    pkg_a = Package(
        type="pypi", name="a", version="1.0", id="pip+a$1.0",
        score={}, alerts=[], direct=True,
    )
    pkg_b = Package(
        type="pypi", name="b", version="1.0", id="pip+b$1.0",
        score={}, alerts=[], direct=False,
    )
    pkg_c = Package(
        type="pypi", name="c", version="1.0", id="pip+c$1.0",
        score={}, alerts=[], direct=True,
    )
    diff = Diff(packages={"id-a": pkg_a, "id-b": pkg_b, "id-c": pkg_c})
    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    payload = build_fossa_attribution_payload(diff, config)
    direct_names = sorted(d["package"] for d in payload["directDependencies"])
    deep_names = sorted(d["package"] for d in payload["deepDependencies"])
    assert direct_names == ["a", "c"]
    assert deep_names == ["b"]


def test_dependency_paths_direct_package_is_name_only():
    from socketsecurity.fossa_compat import _compute_dependency_paths
    pkg = Package(
        type="pypi", name="requests", version="2.31.0",
        id="pip+requests$2.31.0", score={}, alerts=[], direct=True,
    )
    paths = _compute_dependency_paths(pkg, {"pip+requests$2.31.0": pkg})
    assert paths == ["requests"]


def test_dependency_paths_transitive_chains_through_ancestor_name():
    from socketsecurity.fossa_compat import _compute_dependency_paths
    parent = Package(
        type="pypi", name="requests", version="2.31.0",
        id="parent-id", score={}, alerts=[], direct=True,
    )
    child = Package(
        type="pypi", name="certifi", version="2024.7.4",
        id="child-id", score={}, alerts=[], direct=False,
        topLevelAncestors=["parent-id"],
    )
    lookup = {"parent-id": parent, "child-id": child}
    assert _compute_dependency_paths(child, lookup) == ["requests > certifi"]


def test_dependency_paths_multi_ancestor_emits_one_per_root():
    from socketsecurity.fossa_compat import _compute_dependency_paths
    p1 = Package(type="pypi", name="boto3", version="1.0", id="p1",
                 score={}, alerts=[], direct=True)
    p2 = Package(type="pypi", name="botocore", version="1.0", id="p2",
                 score={}, alerts=[], direct=True)
    child = Package(
        type="pypi", name="jmespath", version="1.0", id="c",
        score={}, alerts=[], direct=False,
        topLevelAncestors=["p1", "p2"],
    )
    lookup = {"p1": p1, "p2": p2, "c": child}
    assert sorted(_compute_dependency_paths(child, lookup)) == [
        "boto3 > jmespath",
        "botocore > jmespath",
    ]


def test_dependency_paths_missing_ancestor_falls_back_to_name():
    from socketsecurity.fossa_compat import _compute_dependency_paths
    pkg = Package(
        type="pypi", name="orphan", version="1.0", id="o",
        score={}, alerts=[], direct=False,
        topLevelAncestors=["missing-id"],
    )
    assert _compute_dependency_paths(pkg, {"o": pkg}) == ["orphan"]


def test_vulnerability_version_ranges_sourced_from_socket_fields():
    """affectedVersionRanges/patchedVersionRanges come from Socket's singular fields, wrapped."""
    from socketsecurity.fossa_compat import _build_vulnerability_entry
    issue = Issue(
        type="criticalCVE",
        severity="high",
        key="CVE-2024-12345_pip+requests",
        pkg_type="pypi",
        pkg_name="requests",
        pkg_version="2.30.0",
        props={
            "ghsaId": "GHSA-aaaa-bbbb-cccc",
            "cveId": "CVE-2024-12345",
            "cvss": 7.5,
            "vulnerableVersionRange": ">=2.0.0,<2.31.1",
            "firstPatchedVersionIdentifier": "2.31.1",
            "cwes": ["CWE-200"],
        },
    )
    package = Package(
        type="pypi",
        name="requests",
        version="2.30.0",
        id="pip+requests$2.30.0",
        score={},
        alerts=[],
        direct=True,
    )
    project = {"branch": "main", "id": "acme$x", "project": "acme", "projectId": "acme", "revision": "x", "url": "u"}
    entry = _build_vulnerability_entry(issue, package, project, index=1)
    assert entry["affectedVersionRanges"] == [">=2.0.0,<2.31.1"]
    assert entry["patchedVersionRanges"] == ["2.31.1"]
    assert entry["remediation"]["partialFix"] == "2.31.1"
    assert entry["remediation"]["completeFix"] == "2.31.1"
