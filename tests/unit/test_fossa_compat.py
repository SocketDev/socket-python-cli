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


def test_fossa_attribution_payload_shape_is_stable():
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
            url="https://socket.dev/pypi/package/requests/overview/2.31.0",
            license="Apache-2.0",
            licenseDetails=[{"id": "Apache-2.0"}],
            licenseAttrib=[{"id": "Apache-2.0"}],
            purl="pkg:pypi/requests@2.31.0",
        )
    }

    payload = build_fossa_attribution_payload(diff, config)

    assert sorted(payload.keys()) == ["dependencies", "project"]
    assert sorted(payload["project"].keys()) == sorted(EXPECTED_PROJECT_KEYS)
    assert payload["dependencies"] == [{
        "id": "pkg-1",
        "name": "requests",
        "version": "2.31.0",
        "ecosystem": "pip",
        "direct": True,
        "url": "https://socket.dev/pypi/package/requests/overview/2.31.0",
        "purl": "pkg:pypi/requests@2.31.0",
        "declaredLicense": "Apache-2.0",
        "licenseDetails": [{"id": "Apache-2.0"}],
        "licenseAttrib": [{"id": "Apache-2.0"}],
    }]


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
