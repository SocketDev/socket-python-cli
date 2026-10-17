"""Diff identity tests across the real Core, SDK, and HTTP boundaries."""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from socketdev import socketdev
from socketdev.fullscans import FullScanParams, SocketArtifact

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.report_output import build_socket_json_report
from socketsecurity.core.socket_config import SocketConfig
from tests.support.socket_api_fixture import (
    SocketApiFixture,
    SocketRequest,
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


@pytest.fixture
def core(socket_api: SocketApiFixture) -> Core:
    sdk = socketdev(token="fictional-local-only", timeout=3)
    sdk.api.api_url = socket_api.base_url
    return Core(config=SocketConfig(api_key="fictional-local-only"), sdk=sdk)


def empty_artifacts() -> dict[str, list[object]]:
    return {
        "added": [],
        "removed": [],
        "unchanged": [],
        "replaced": [],
        "updated": [],
    }


def diff_response(diff_id: str) -> dict[str, object]:
    return {"diff_scan": {"id": diff_id}}


def completion_response() -> dict[str, object]:
    return {"diff_scan": {"artifacts": empty_artifacts()}}


def stream_diff_response() -> dict[str, object]:
    commit = {
        "repository_id": "repo-fixture",
        "branch": "main",
        "id": "scan-fixture",
        "organization_id": "org-fixture",
        "committers": [],
    }
    return {
        "before": commit,
        "after": commit,
        "diff_report_url": "https://socket.dev/fixture",
        "artifacts": empty_artifacts(),
    }


def install_primary_routes(api: SocketApiFixture, diff_id: str) -> None:
    api.route(
        "POST",
        "orgs/fixture-org/diff-scans/from-ids",
        SocketResponse(201, diff_response(diff_id)),
    )
    api.route(
        "GET",
        f"orgs/fixture-org/diff-scans/{diff_id}",
        SocketResponse(200, completion_response()),
    )


def test_primary_diff_scan_uses_server_resource_id_and_real_cached_get(
    core: Core,
    socket_api: SocketApiFixture,
) -> None:
    install_primary_routes(socket_api, "server-diff-id")

    result = core._get_diff_scan_result("baseline-scan-id", "new-scan-id")

    assert result.diff_scan_id == "server-diff-id"
    assert result.diff_url is None
    assert result.artifacts.added == []
    assert [request.path for request in socket_api.requests] == [
        "organizations",
        "orgs/fixture-org/diff-scans/from-ids",
        "orgs/fixture-org/diff-scans/server-diff-id",
    ]
    create = socket_api.requests[1]
    assert create.query["before"] == ["baseline-scan-id"]
    assert create.query["after"] == ["new-scan-id"]
    assert socket_api.requests[2].query == {"cached": ["true"]}


def test_duplicate_conflict_uses_listed_id_and_cached_get(
    core: Core,
    socket_api: SocketApiFixture,
) -> None:
    def duplicate(_request: SocketRequest) -> SocketResponse:
        return SocketResponse(409, {"error": {"message": "duplicate"}})

    socket_api.route("POST", "orgs/fixture-org/diff-scans/from-ids", duplicate)
    socket_api.route(
        "GET",
        "orgs/fixture-org/diff-scans",
        SocketResponse(200, {"results": [{"id": "listed-diff-id"}]}),
    )
    socket_api.route(
        "GET",
        "orgs/fixture-org/diff-scans/listed-diff-id",
        SocketResponse(
            200,
            {
                "diff_scan": {
                    "html_url": "https://reports.example.invalid/duplicate-diff?via=get#done",
                    "before_full_scan": {
                        "id": "baseline-scan-id",
                        "html_url": "https://reports.example.invalid/duplicate-before",
                    },
                    "after_full_scan": {
                        "id": "new-scan-id",
                        "html_url": "https://reports.example.invalid/duplicate-after",
                    },
                    "artifacts": empty_artifacts(),
                }
            },
        ),
    )

    result = core._get_diff_scan_result("baseline-scan-id", "new-scan-id")

    assert result.diff_scan_id == "listed-diff-id"
    assert result.diff_url == "https://reports.example.invalid/duplicate-diff?via=get#done"
    assert result.old_scan_url == "https://reports.example.invalid/duplicate-before"
    assert result.new_scan_url == "https://reports.example.invalid/duplicate-after"
    assert [request.path for request in socket_api.requests] == [
        "organizations",
        "orgs/fixture-org/diff-scans/from-ids",
        "orgs/fixture-org/diff-scans",
        "orgs/fixture-org/diff-scans/listed-diff-id",
    ]
    assert socket_api.requests[2].query == {
        "before_full_scan_id": ["baseline-scan-id"],
        "after_full_scan_id": ["new-scan-id"],
        "per_page": ["1"],
    }
    assert socket_api.requests[3].query == {"cached": ["true"]}


def test_primary_result_uses_server_urls_and_checks_nested_scan_ids(
    core: Core,
    socket_api: SocketApiFixture,
) -> None:
    socket_api.route(
        "POST",
        "orgs/fixture-org/diff-scans/from-ids",
        SocketResponse(201, diff_response("server-diff-id")),
    )
    socket_api.route(
        "GET",
        "orgs/fixture-org/diff-scans/server-diff-id",
        SocketResponse(
            200,
            {
                "diff_scan": {
                    "html_url": "https://reports.example.invalid/diff?pair=server#view",
                    "before_full_scan": {
                        "id": "requested-before",
                        "html_url": "https://reports.example.invalid/before?q=1",
                    },
                    "after_full_scan": {
                        "id": "wrong-after",
                        "html_url": "https://reports.example.invalid/wrong",
                    },
                    "artifacts": empty_artifacts(),
                }
            },
        ),
    )

    result = core._get_diff_scan_result("requested-before", "requested-after")

    assert result.diff_url == "https://reports.example.invalid/diff?pair=server#view"
    assert result.old_scan_url == "https://reports.example.invalid/before?q=1"
    assert result.new_scan_url is None


def test_streaming_comparison_carries_sdk_diff_report_url(
    core: Core,
    socket_api: SocketApiFixture,
) -> None:
    socket_api.route(
        "POST",
        "orgs/fixture-org/diff-scans/from-ids",
        SocketResponse(403, {"error": {"message": "forbidden"}}),
    )
    socket_api.route(
        "GET",
        "orgs/fixture-org/full-scans/diff",
        SocketResponse(200, stream_diff_response()),
    )

    result = core._get_package_comparison("baseline-scan-id", "new-scan-id")

    assert result.diff_scan_id is None
    assert result.diff_url == "https://socket.dev/fixture"
    assert result.old_scan_url is None
    assert result.new_scan_url is None


@pytest.mark.parametrize("failure_status", [403, 200])
def test_streaming_fallback_does_not_return_attempted_diff_id(
    core: Core,
    socket_api: SocketApiFixture,
    failure_status: int,
) -> None:
    if failure_status == 403:
        socket_api.route(
            "POST",
            "orgs/fixture-org/diff-scans/from-ids",
            SocketResponse(403, {"error": {"message": "forbidden"}}),
        )
    else:
        socket_api.route(
            "POST",
            "orgs/fixture-org/diff-scans/from-ids",
            SocketResponse(201, diff_response("abandoned-diff-id")),
        )
        socket_api.route(
            "GET",
            "orgs/fixture-org/diff-scans/abandoned-diff-id",
            SocketResponse(200, {"diff_scan": {"artifacts": None}}),
        )
    socket_api.route(
        "GET",
        "orgs/fixture-org/full-scans/diff",
        SocketResponse(200, stream_diff_response()),
    )

    result = core._get_package_comparison(
        "baseline-scan-id", "new-scan-id", include_license_details=False
    )

    assert result.diff_scan_id is None
    assert result.added_packages == {}
    assert result.removed_packages == {}
    assert result.packages == {}
    fallback = socket_api.requests[-1]
    assert fallback.path == "orgs/fixture-org/full-scans/diff"
    assert fallback.query == {
        "before": ["baseline-scan-id"],
        "after": ["new-scan-id"],
        "include_license_details": ["false"],
    }


def test_compatibility_wrappers_preserve_legacy_return_shapes(
    core: Core,
    socket_api: SocketApiFixture,
) -> None:
    install_primary_routes(socket_api, "wrapper-diff-id")

    artifacts = core.get_diff_scan_artifacts("baseline-scan-id", "new-scan-id")
    added, removed, packages = core.get_added_and_removed_packages(
        "baseline-scan-id", "new-scan-id"
    )

    assert (artifacts.added, artifacts.removed) == ([], [])
    assert added == {}
    assert removed == {}
    assert packages == {}
    comparison_requests = socket_api.requests[1:]
    assert len(comparison_requests) == 4
    assert [request.path for request in comparison_requests] == [
        "orgs/fixture-org/diff-scans/from-ids",
        "orgs/fixture-org/diff-scans/wrapper-diff-id",
        "orgs/fixture-org/diff-scans/from-ids",
        "orgs/fixture-org/diff-scans/wrapper-diff-id",
    ]


@pytest.mark.parametrize("comparison_succeeds", [True, False])
@pytest.mark.parametrize("include_license_details", [True, False])
@pytest.mark.parametrize("null_urls", [True, False])
def test_create_new_diff_retains_real_empty_baseline_id(
    core: Core,
    socket_api: SocketApiFixture,
    tmp_path,
    comparison_succeeds: bool,
    include_license_details: bool,
    null_urls: bool,
) -> None:
    socket_api.route(
        "GET",
        "orgs/fixture-org/repos/fixture-repo",
        SocketResponse(
            200,
            {
                "id": "repository-id",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "head_full_scan_id": "",
                "name": "fixture-repo",
                "slug": "fixture-repo",
                "description": "",
                "homepage": "https://example.invalid/fixture-repo",
                "visibility": "private",
                "archived": False,
                "default_branch": "main",
            },
        ),
    )
    created_scan_ids = iter(("temporary-baseline-id", "new-full-scan-id"))

    def create_full_scan(_request: SocketRequest) -> SocketResponse:
        scan_id = next(created_scan_ids)
        return SocketResponse(
            201,
            {
                "id": scan_id,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "organization_id": "org-fixture",
                "repository_id": "repository-id",
                "branch": "feature",
                "html_report_url": f"https://socket.dev/scan/{scan_id}",
            },
        )

    socket_api.route("POST", "orgs/fixture-org/full-scans", create_full_scan)
    if comparison_succeeds:
        socket_api.route(
            "POST",
            "orgs/fixture-org/diff-scans/from-ids",
            SocketResponse(201, diff_response("new-comparison-id")),
        )
        socket_api.route(
            "GET",
            "orgs/fixture-org/diff-scans/new-comparison-id",
            SocketResponse(
                200,
                {
                    "diff_scan": {
                        "html_url": None
                        if null_urls
                        else "https://reports.example.invalid/diff?canonical=1#comparison",
                        "before_full_scan": {
                            "id": "temporary-baseline-id",
                            "html_url": None
                            if null_urls
                            else "https://reports.example.invalid/before?source=get",
                        },
                        "after_full_scan": {
                            "id": "new-full-scan-id",
                            "html_url": None
                            if null_urls
                            else "https://reports.example.invalid/after?source=get#scan",
                        },
                        "artifacts": empty_artifacts(),
                    }
                },
            ),
        )
    else:
        socket_api.route(
            "POST",
            "orgs/fixture-org/diff-scans/from-ids",
            SocketResponse(403, {"error": {"message": "forbidden"}}),
        )
        socket_api.route(
            "GET",
            "orgs/fixture-org/full-scans/diff",
            SocketResponse(200, stream_diff_response()),
        )
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("sample-package==1.0.0\n")
    params = FullScanParams(
        repo="fixture-repo",
        org_slug="fixture-org",
        branch="feature",
        commit_hash="new-commit",
    )
    params.include_license_details = include_license_details

    diff = core.create_new_diff(
        [str(tmp_path)],
        params,
        explicit_files=[str(manifest)],
        base_paths=[str(tmp_path)],
    )

    assert diff.id == "new-full-scan-id"
    assert diff.new_scan_id == "new-full-scan-id"
    assert diff.old_scan_id == "temporary-baseline-id"
    assert diff.diff_scan_id == ("new-comparison-id" if comparison_succeeds else None)
    expected_new_scan_url = (
        "https://socket.dev/scan/new-full-scan-id"
        if null_urls or not comparison_succeeds
        else "https://reports.example.invalid/after?source=get#scan"
    )
    expected_report_url = (
        expected_new_scan_url
        if include_license_details
        else ""
    )
    if not include_license_details:
        report_base, separator, fragment = expected_new_scan_url.partition("#")
        query_separator = "&" if "?" in report_base else "?"
        expected_report_url = (
            f"{report_base}{query_separator}include_license_details=false"
            f"{separator}{fragment}" if separator else
            f"{report_base}{query_separator}include_license_details=false"
        )
    assert diff.new_scan_url == expected_new_scan_url
    assert diff.report_url == expected_report_url
    report = build_socket_json_report(
        diff,
        CliConfig(
            api_token="fictional-local-only",
            repo="fixture-repo",
            legal=False,
        ),
    )
    assert report["full_scan_id"] == "new-full-scan-id"
    assert report["diff_scan_id"] == (
        "new-comparison-id" if comparison_succeeds else None
    )
    assert report["old_scan_id"] == "temporary-baseline-id"
    assert report["new_scan_id"] == "new-full-scan-id"
    assert report["diff_url"] == diff.diff_url
    assert report["old_scan_url"] == diff.old_scan_url
    assert report["new_scan_url"] == expected_new_scan_url
    assert report["report_url"] == expected_report_url
    if comparison_succeeds and not null_urls:
        assert diff.diff_url == "https://reports.example.invalid/diff?canonical=1#comparison"
        assert diff.old_scan_url == "https://reports.example.invalid/before?source=get"
    elif comparison_succeeds:
        assert diff.diff_url is None
        assert diff.old_scan_url == "https://socket.dev/scan/temporary-baseline-id"
    else:
        assert diff.diff_url == "https://socket.dev/fixture"
        assert diff.old_scan_url == "https://socket.dev/scan/temporary-baseline-id"
        assert diff.new_scan_url == "https://socket.dev/scan/new-full-scan-id"
    assert sum(
        request.path == "orgs/fixture-org/full-scans/diff"
        for request in socket_api.requests
    ) == int(not comparison_succeeds)
    full_scan_requests = [
        request
        for request in socket_api.requests
        if request.path == "orgs/fixture-org/full-scans"
    ]
    assert len(full_scan_requests) == 2
    assert all(
        "multipart/form-data" in request.headers["Content-Type"]
        for request in full_scan_requests
    )
    assert b"sample-package==1.0.0" in full_scan_requests[1].body
    assert full_scan_requests[0].query["tmp"] == ["True"]
    assert full_scan_requests[1].query["commit_hash"] == ["new-commit"]
    comparison_create = next(
        request
        for request in socket_api.requests
        if request.path == "orgs/fixture-org/diff-scans/from-ids"
    )
    assert comparison_create.query["before"] == ["temporary-baseline-id"]
    assert comparison_create.query["after"] == ["new-full-scan-id"]


@pytest.mark.parametrize("enable_json", [False, True])
def test_full_scan_identity_is_preserved_with_findings_disabled_or_enabled(
    socket_api: SocketApiFixture,
    tmp_path,
    enable_json: bool,
) -> None:
    cli_config = None
    if enable_json:
        cli_config = CliConfig(
            api_token="fictional-local-only",
            repo="fixture-repo",
            enable_json=True,
        )
    sdk = socketdev(token="fictional-local-only", timeout=3)
    sdk.api.api_url = socket_api.base_url
    core = Core(
        config=SocketConfig(api_key="fictional-local-only"),
        sdk=sdk,
        cli_config=cli_config,
    )
    socket_api.route(
        "POST",
        "orgs/fixture-org/full-scans",
        SocketResponse(
            201,
            {
                "id": "full-scan-id",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "organization_id": "org-fixture",
                "repository_id": "repository-fixture",
                "branch": "feature",
                "html_report_url": "https://socket.dev/scan/full-scan-id",
            },
        ),
    )
    if enable_json:
        artifact = SocketArtifact.from_dict(
            {
                "id": "artifact-fixture-id",
                "type": "npm",
                "name": "sample-package",
                "version": "1.0.0",
                "alerts": [],
                "topLevelAncestors": [],
                "direct": True,
            }
        )
        socket_api.route(
            "GET",
            "orgs/fixture-org/full-scans/full-scan-id",
            SocketResponse(
                200,
                {},
                raw_body=json.dumps(artifact.to_dict()).encode("utf-8"),
            ),
        )
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("sample-package==1.0.0\n")
    params = FullScanParams(
        repo="fixture-repo",
        org_slug="fixture-org",
        branch="feature",
    )

    result = core.create_full_scan_with_report_url(
        [str(tmp_path)], params, explicit_files=[str(manifest)]
    )

    assert result.id == result.new_scan_id == "full-scan-id"
    assert result.old_scan_id is None
    assert result.diff_scan_id is None
    assert result.is_full_scan is True
    assert result.alerts_fetched is enable_json
    assert result.new_scan_url == "https://socket.dev/scan/full-scan-id"
    assert result.old_scan_url is None
    assert result.report_url == result.diff_url == result.new_scan_url
    report = build_socket_json_report(
        result,
        cli_config
        or CliConfig(api_token="fictional-local-only", repo="fixture-repo"),
    )
    assert report["full_scan_id"] == "full-scan-id"
    assert report["diff_scan_id"] is None
    assert report["old_scan_id"] is None
    assert report["new_scan_id"] == "full-scan-id"
    assert report["old_scan_url"] is None
    assert report["new_scan_url"] == "https://socket.dev/scan/full-scan-id"
    if enable_json:
        assert result.packages["artifact-fixture-id"].purl == "npm/sample-package@1.0.0"
    findings_requests = [
        request
        for request in socket_api.requests
        if request.path == "orgs/fixture-org/full-scans/full-scan-id"
    ]
    assert len(findings_requests) == int(enable_json)


def test_no_change_paths_keep_sentinels_without_transport_calls(
    core: Core,
    socket_api: SocketApiFixture,
) -> None:
    request_count_after_setup = len(socket_api.requests)
    params = FullScanParams(repo="fixture-repo")

    no_diff = core.create_new_diff([], params, no_change=True)
    no_scan = core.create_full_scan_with_report_url([], params, no_change=True)

    assert no_diff.id == "NO_DIFF_RAN"
    assert no_scan.id == "NO_SCAN_RAN"
    for result in (no_diff, no_scan):
        assert result.new_scan_id is None
        assert result.old_scan_id is None
        assert result.diff_scan_id is None
        assert result.old_scan_url is None
        assert result.new_scan_url is None
        report = build_socket_json_report(
            result, CliConfig(api_token="fictional-local-only", repo="fixture-repo")
        )
        assert report["diff_scan_id"] is None
        assert report["old_scan_id"] is None
        assert report["new_scan_id"] is None
        assert report["old_scan_url"] is None
        assert report["new_scan_url"] is None
        assert report["full_scan_id"] == result.id
    assert len(socket_api.requests) == request_count_after_setup
