from __future__ import annotations

from collections.abc import Iterator

import pytest
from socketdev import socketdev
from socketdev.exceptions import APIFailure
from socketdev.fullscans import FullScanParams

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.socket_config import SocketConfig
from tests.support.socket_api_fixture import (
    SocketApiFixture,
    SocketResponse,
    socket_api_fixture,
)


@pytest.fixture
def socket_api() -> Iterator[SocketApiFixture]:
    fixture = socket_api_fixture()
    try:
        yield fixture
    finally:
        fixture.close()


def create_core(
    api: SocketApiFixture,
    cli_config: CliConfig | None = None,
) -> Core:
    sdk = socketdev(token="fictional-local-only", timeout=3)
    sdk.api.api_url = api.base_url
    return Core(
        config=SocketConfig(api_key="fictional-local-only"),
        sdk=sdk,
        cli_config=cli_config,
    )


def full_scan_response(scan_id: str) -> SocketResponse:
    return SocketResponse(
        201,
        {
            "id": scan_id,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "organization_id": "org-fixture",
            "repository_id": "repository-fixture",
            "branch": "feature",
            "html_report_url": f"https://socket.dev/scan/{scan_id}",
        },
    )


def install_diff_routes(api: SocketApiFixture) -> None:
    api.route(
        "POST",
        "orgs/fixture-org/diff-scans/from-ids",
        SocketResponse(201, {"diff_scan": {"id": "diff-resource-id"}}),
    )
    api.route(
        "GET",
        "orgs/fixture-org/diff-scans/diff-resource-id",
        SocketResponse(
            200,
            {
                "diff_scan": {
                    "artifacts": {
                        "added": [],
                        "removed": [],
                        "unchanged": [],
                        "replaced": [],
                        "updated": [],
                    }
                }
            },
        ),
    )


def test_scan_configuration_omits_absolute_and_manifest_paths(caplog) -> None:
    params = FullScanParams(
        repo="repo-service",
        branch="feature",
        workspace="engineering",
    )

    with caplog.at_level("INFO", logger="socketdev"):
        Core._log_scan_configuration(
            ["/private/build/repo/service"],
            params,
            ["/private/build/repo/service/requirements.txt"],
            manifest_source="provided",
            base_paths=["/private/build/repo"],
        )

    message = caplog.messages[-1]
    assert 'workspace="engineering"' in message
    assert 'roots=["service"]' in message
    assert "manifests=1 manifest_source=provided" in message
    assert "/private/build" not in message
    assert "requirements.txt" not in message


def test_multiple_scan_paths_are_uploaded_as_one_combined_full_scan(
    caplog,
    socket_api: SocketApiFixture,
    tmp_path,
) -> None:
    cli_config = CliConfig(
        api_token="fictional-local-only",
        repo="fixture-repo",
        base_scan_id="baseline-scan-id",
    )
    core = create_core(socket_api, cli_config)
    socket_api.route(
        "POST",
        "orgs/fixture-org/full-scans",
        full_scan_response("new-full-scan-id"),
    )
    install_diff_routes(socket_api)
    frontend = tmp_path / "frontend" / "package.json"
    backend = tmp_path / "backend" / "requirements.txt"
    frontend.parent.mkdir()
    backend.parent.mkdir()
    frontend.write_text('{"dependencies":{"sample":"1.0.0"}}\n')
    backend.write_text("sample-package==1.0.0\n")
    params = FullScanParams(
        repo="fixture-repo",
        org_slug="fixture-org",
        branch="feature",
        commit_hash="new-commit",
    )
    params.include_license_details = True

    with caplog.at_level("INFO", logger="socketdev"):
        result = core.create_new_diff(
            [str(frontend.parent), str(backend.parent)],
            params,
            explicit_files=[str(frontend), str(backend)],
            base_paths=[str(tmp_path)],
        )

    full_scan_requests = [
        request
        for request in socket_api.requests
        if request.path == "orgs/fixture-org/full-scans"
    ]
    assert len(full_scan_requests) == 1
    assert result.id == result.new_scan_id == "new-full-scan-id"
    assert result.old_scan_id == "baseline-scan-id"
    assert result.diff_scan_id == "diff-resource-id"
    assert (
        'Scan configuration: repo="fixture-repo" workspace=null '
        'scan_type=null roots=["frontend","backend"] manifests=2 '
        "manifest_source=provided"
    ) in caplog.messages


def test_empty_baseline_creation_keeps_its_actual_id(
    socket_api: SocketApiFixture,
    tmp_path,
) -> None:
    core = create_core(socket_api)
    socket_api.route(
        "GET",
        "orgs/fixture-org/repos/fixture-repo",
        SocketResponse(
            200,
            {
                "id": "repository-id",
                "head_full_scan_id": "",
                "name": "fixture-repo",
                "slug": "fixture-repo",
                "description": "",
                "homepage": "",
                "visibility": "private",
                "archived": False,
                "default_branch": "main",
            },
        ),
    )
    created_scan_ids: Iterator[str] = iter(("empty-baseline-id", "new-scan-id"))
    socket_api.route(
        "POST",
        "orgs/fixture-org/full-scans",
        lambda _request: full_scan_response(next(created_scan_ids)),
    )
    install_diff_routes(socket_api)
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("sample-package==1.0.0\n")
    params = FullScanParams(
        repo="fixture-repo",
        org_slug="fixture-org",
        branch="feature",
        commit_hash="new-commit",
    )
    params.include_license_details = True

    result = core.create_new_diff(
        [str(tmp_path)],
        params,
        explicit_files=[str(manifest)],
        base_paths=[str(tmp_path)],
    )

    assert result.old_scan_id == "empty-baseline-id"
    assert result.new_scan_id == "new-scan-id"
    assert result.diff_scan_id == "diff-resource-id"
    comparison_create = next(
        request
        for request in socket_api.requests
        if request.path == "orgs/fixture-org/diff-scans/from-ids"
    )
    assert comparison_create.query["before"] == ["empty-baseline-id"]
    assert comparison_create.query["after"] == ["new-scan-id"]


def test_full_scan_upload_failure_comes_from_real_http_response(
    socket_api: SocketApiFixture,
    tmp_path,
) -> None:
    cli_config = CliConfig(
        api_token="fictional-local-only",
        repo="fixture-repo",
        base_scan_id="baseline-scan-id",
    )
    core = create_core(socket_api, cli_config)
    socket_api.route(
        "POST",
        "orgs/fixture-org/full-scans",
        SocketResponse(500, {"error": {"message": "local fixture failure"}}),
    )
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("sample-package==1.0.0\n")
    params = FullScanParams(
        repo="fixture-repo",
        org_slug="fixture-org",
        branch="feature",
    )
    params.include_license_details = True

    with pytest.raises(APIFailure, match="local fixture failure"):
        core.create_new_diff([str(tmp_path)], params, explicit_files=[str(manifest)])

    assert [request.path for request in socket_api.requests] == [
        "organizations",
        "orgs/fixture-org/full-scans",
    ]


def test_diff_fallback_uses_real_streaming_endpoint_and_logs_mode(
    caplog,
    socket_api: SocketApiFixture,
) -> None:
    core = create_core(socket_api)
    socket_api.route(
        "POST",
        "orgs/fixture-org/diff-scans/from-ids",
        SocketResponse(403, {"error": {"message": "forbidden"}}),
    )
    socket_api.route(
        "GET",
        "orgs/fixture-org/full-scans/diff",
        SocketResponse(
            200,
            {
                "before": {
                    "repository_id": "repo-id",
                    "branch": "main",
                    "id": "baseline-scan",
                    "organization_id": "org-fixture",
                    "committers": [],
                },
                "after": {
                    "repository_id": "repo-id",
                    "branch": "feature",
                    "id": "new-scan",
                    "organization_id": "org-fixture",
                    "committers": [],
                },
                "diff_report_url": "https://socket.dev/fixture/diff",
                "artifacts": {
                    "added": [],
                    "removed": [],
                    "unchanged": [],
                    "replaced": [],
                    "updated": [],
                },
            },
        ),
    )

    with caplog.at_level("INFO", logger="socketdev"):
        result = core._get_package_comparison(
            "baseline-scan-id",
            "new-scan-id",
            include_license_details=True,
        )

    assert result.diff_scan_id is None
    assert (
        "Diff comparison mode: requested=diff-scan effective=streaming reason=APIAccessDenied"
        in caplog.messages
    )
    stream_request = socket_api.requests[-1]
    assert stream_request.query == {
        "before": ["baseline-scan-id"],
        "after": ["new-scan-id"],
        "include_license_details": ["true"],
    }
