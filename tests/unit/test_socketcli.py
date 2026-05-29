import sys

import pytest

from socketsecurity.core.classes import Diff, Package
from socketsecurity import socketcli
from socketsecurity.socketcli import build_license_artifact_payload


# ---------------------------------------------------------------------------
# Exit-code-on-api-error (flag-only, non-breaking for 2.3.x).
#
# Default behavior is unchanged from prior releases: unexpected errors exit 3,
# and --disable-blocking forces exit 0 for everything. The flag only changes
# the code when explicitly set, and --disable-blocking still takes precedence.
# ---------------------------------------------------------------------------


def _run_cli_expecting_exit(monkeypatch, argv, boom=None):
    def fail_main_code():
        raise (boom or RuntimeError("infra boom"))

    monkeypatch.setattr(socketcli, "main_code", fail_main_code)
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()
    return exc_info.value.code


def test_unexpected_error_exits_3_by_default(monkeypatch):
    code = _run_cli_expecting_exit(monkeypatch, ["socketcli", "--api-token", "test"])
    assert code == 3


def test_exit_code_on_api_error_remaps_failure(monkeypatch):
    code = _run_cli_expecting_exit(
        monkeypatch,
        ["socketcli", "--api-token", "test", "--exit-code-on-api-error", "100"],
    )
    assert code == 100


def test_disable_blocking_overrides_exit_code_on_api_error(monkeypatch):
    # The documented interaction: --disable-blocking forces exit 0 for ALL
    # outcomes and therefore overrides --exit-code-on-api-error. A user who
    # sets both gets 0, NOT 100 -- this guards against silently regressing
    # that precedence (which would break the documented soft_fail guidance).
    code = _run_cli_expecting_exit(
        monkeypatch,
        [
            "socketcli", "--api-token", "test",
            "--exit-code-on-api-error", "100",
            "--disable-blocking",
        ],
    )
    assert code == 0


def test_keyboard_interrupt_still_exits_2(monkeypatch):
    code = _run_cli_expecting_exit(
        monkeypatch, ["socketcli", "--api-token", "test"], boom=KeyboardInterrupt()
    )
    assert code == 2


# ---------------------------------------------------------------------------
# Buildkite-aware infrastructure error formatting.
# ---------------------------------------------------------------------------


def test_emit_infra_error_no_buildkite_has_no_markers(monkeypatch, capsys, caplog):
    monkeypatch.setattr(socketcli, "IS_BUILDKITE", False)
    with caplog.at_level("ERROR", logger="socketcli"):
        socketcli._emit_infrastructure_error("something failed")
    out = capsys.readouterr().out
    assert "^^^ +++" not in out
    assert "--- :warning:" not in out
    assert "soft_fail" not in "\n".join(r.getMessage() for r in caplog.records)


def test_emit_infra_error_buildkite_emits_markers(monkeypatch, capsys, caplog):
    monkeypatch.setattr(socketcli, "IS_BUILDKITE", True)
    with caplog.at_level("ERROR", logger="socketcli"):
        socketcli._emit_infrastructure_error("something failed")
    out = capsys.readouterr().out
    assert "^^^ +++" in out
    assert "--- :warning: Socket infrastructure error" in out
    assert "soft_fail" in "\n".join(r.getMessage() for r in caplog.records)


def test_emit_infra_error_traceback_gated(monkeypatch, capsys):
    monkeypatch.setattr(socketcli, "IS_BUILDKITE", False)
    try:
        raise ValueError("boom")
    except ValueError:
        socketcli._emit_infrastructure_error("wrapped", include_traceback=True)
    err = capsys.readouterr().err
    assert "Traceback" in err and "ValueError: boom" in err


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
        "copyrightsByLicense": {},
        "deepDependencies": [],
        "directDependencies": [],
        "licenses": {},
        "project": {"name": "owner/repo", "revision": "scan-1"},
    }


def test_fossa_attribution_file_is_written_indented(tmp_path):
    """fossa-sbom.json should be written with indent=2, matching fossa-analyze.json."""
    import json
    from types import SimpleNamespace

    from socketsecurity import socketcli

    target = tmp_path / "fossa-sbom.json"
    config = SimpleNamespace(license_file_name=str(target))
    payload = {
        "copyrightsByLicense": {},
        "deepDependencies": [],
        "directDependencies": [],
        "licenses": {},
        "project": {"name": "x", "revision": "y"},
    }
    socketcli._write_attribution_file(config, payload)
    content = target.read_text()
    assert "\n  " in content, f"Expected indented JSON, got: {content!r}"
    assert json.loads(content) == payload


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

    assert payload["project"] == {"name": "owner/repo", "revision": "scan-1"}
    assert payload["directDependencies"] == [{
        "authors": [],
        "dependencyPaths": ["requests"],
        "description": "",
        "downloadUrl": "",
        "hash": None,
        "isGolang": None,
        "licenses": [{"attribution": "", "name": "Apache-2.0"}],
        "notes": [],
        "otherLicenses": [],
        "package": "requests",
        "projectUrl": "",
        "source": "pip",
        "title": "requests",
        "version": "2.31.0",
    }]
    assert payload["deepDependencies"] == []
    assert payload["copyrightsByLicense"] == {}
    assert payload["licenses"] == {}
