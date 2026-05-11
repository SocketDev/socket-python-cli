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
