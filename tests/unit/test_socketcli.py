from socketsecurity.core.classes import Diff, Package
from socketsecurity.socketcli import build_license_artifact_payload


def test_build_license_artifact_payload_without_packages_returns_empty_dict():
    diff = Diff()

    payload = build_license_artifact_payload(diff)

    assert payload == {}


def test_build_license_artifact_payload_serializes_package_fields():
    diff = Diff()
    diff.packages = {
        "pypi/requests@2.31.0": Package(
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
            purl="requests@2.31.0",
        )
    }

    payload = build_license_artifact_payload(diff)

    assert payload == {
        "pkg-1": {
            "id": "pkg-1",
            "name": "requests",
            "version": "2.31.0",
            "ecosystem": "pypi",
            "direct": True,
            "url": "https://socket.dev/pypi/package/requests/overview/2.31.0",
            "license": "Apache-2.0",
            "licenseDetails": [{"id": "Apache-2.0"}],
            "licenseAttrib": [{"id": "Apache-2.0"}],
            "purl": "requests@2.31.0",
        }
    }


def test_build_license_artifact_payload_fossa_format_without_packages():
    class Config:
        repo = "owner/repo"
        branch = "main"

    diff = Diff(id="scan-1", report_url="https://socket.dev/report/1")

    payload = build_license_artifact_payload(diff, legal_format="fossa", config=Config())

    assert payload == {
        "project": {
            "branch": "main",
            "id": "owner/repo-scan-1",
            "project": "owner/repo",
            "projectId": "owner/repo",
            "revision": "scan-1",
            "url": "https://socket.dev/report/1",
        },
        "dependencies": [],
    }


def test_build_license_artifact_payload_fossa_format_serializes_dependencies():
    class Config:
        repo = "owner/repo"
        branch = "main"

    diff = Diff(id="scan-1", report_url="https://socket.dev/report/1")
    diff.packages = {
        "pkg:pypi/requests@2.31.0": Package(
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

    payload = build_license_artifact_payload(diff, legal_format="fossa", config=Config())

    assert payload["project"]["projectId"] == "owner/repo"
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
