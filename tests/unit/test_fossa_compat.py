import json
from pathlib import Path

from socketsecurity.config import CliConfig
from socketsecurity.core.classes import Diff, Issue, Package
from socketsecurity.fossa_compat import build_fossa_report_payload


FIXTURE_DIR = Path("/Users/lelia/github/fossa/DependencyScan/Fossa/validation-pipeline")


def test_fossa_report_payload_matches_sample_top_level_shape():
    sample = json.loads(
        (FIXTURE_DIR / "fossa-analyze-11464165-job-011e1ec8-6569-5e69-4f06-baf193d1351e_03172026132742.json").read_text()
    )

    config = CliConfig.from_args(["--api-token", "test", "--legal-format", "fossa"])
    diff = Diff(id="scan-123", report_url="https://socket.dev/report/123")

    payload = build_fossa_report_payload(diff, config)

    assert list(payload.keys()) == list(sample.keys())
    assert sorted(payload["project"].keys()) == sorted(sample["project"].keys())
    assert payload["vulnerability"] == []
    assert payload["licensing"] == []
    assert payload["quality"] == []


def test_fossa_report_payload_vulnerability_keys_cover_sample_shape():
    sample = json.loads(
        (FIXTURE_DIR / "fossa-analyze-11464165-job-7f33e5bd-7764-5d8a-ba2e-506e078b9c3f_03172026132955.json").read_text()
    )
    sample_vulnerability = sample["vulnerability"][0]

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

    assert sorted(generated_vulnerability.keys()) == sorted(sample_vulnerability.keys())
    assert generated_vulnerability["source"]["packageManager"] == sample_vulnerability["source"]["packageManager"]
    assert sorted(generated_vulnerability["source"].keys()) == sorted(sample_vulnerability["source"].keys())
    assert sorted(generated_vulnerability["depths"].keys()) == sorted(sample_vulnerability["depths"].keys())
    assert sorted(generated_vulnerability["statuses"].keys()) == sorted(sample_vulnerability["statuses"].keys())
    assert sorted(generated_vulnerability["remediation"].keys()) == sorted(sample_vulnerability["remediation"].keys())
    assert sorted(generated_vulnerability["epss"].keys()) == sorted(sample_vulnerability["epss"].keys())
