"""Package-change JSON transport coverage across real Core and SDK paths."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from socketdev import socketdev
from socketdev.fullscans import FullScanParams

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.report_output import build_socket_json_report
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


def _core(api: SocketApiFixture) -> Core:
    sdk = socketdev(token="fictional-local-only", timeout=3)
    sdk.api.api_url = api.base_url
    return Core(
        config=SocketConfig(api_key="fictional-local-only"),
        sdk=sdk,
        cli_config=CliConfig(api_token="fictional-local-only", repo="fixture-repo"),
    )


def _score() -> dict[str, int | float | None]:
    return {
        "supplyChain": 0,
        "quality": 0.25,
        "maintenance": 1,
        "vulnerability": None,
        "license": 0,
        "overall": 0.5,
    }


def _artifact(
    artifact_id: str,
    change_type: str,
    name: str,
    version: str,
    *,
    direct: bool = True,
    namespace: str | None = None,
    score: dict[str, int | float | None] | None = None,
    parent_id: str | None = None,
) -> dict[str, object]:
    reference: dict[str, object] = {
        "diffType": change_type,
        "direct": direct,
        "topLevelAncestors": [parent_id] if parent_id else [],
        "dependencies": [],
        "manifestFiles": [{"file": "requirements.txt"}] if direct else [],
        "artifact": {"id": artifact_id},
    }
    artifact: dict[str, object] = {
        "diffType": change_type,
        "id": artifact_id,
        "type": "npm" if namespace else "pypi",
        "name": name,
        "version": version,
        "alerts": [],
        "licenseDetails": [],
        "author": ["Fixture Author"],
        "head" if change_type in ("added", "updated", "unchanged") else "base": [
            reference
        ],
    }
    if namespace:
        artifact["namespace"] = namespace
    if score is not None:
        artifact["score"] = score
    return artifact


def _artifacts() -> dict[str, list[dict[str, object]]]:
    return {
        "added": [
            _artifact("added-id", "added", "added-lib", "1.0.0", score=_score()),
            _artifact(
                "transitive-id",
                "added",
                "transitive-lib",
                "1.1.0",
                direct=False,
                parent_id="added-id",
            ),
        ],
        "updated": [
            _artifact(
                "updated-id",
                "updated",
                "updated-lib",
                "2.0.0",
                namespace="@fictional",
                score=_score(),
            )
        ],
        "removed": [_artifact("removed-id", "removed", "removed-lib", "3.0.0")],
        "replaced": [_artifact("replaced-id", "replaced", "replaced-lib", "0.9.0")],
        "unchanged": [_artifact("unchanged-id", "unchanged", "steady-lib", "4.0.0")],
    }


def _stream_response(
    artifacts: dict[str, list[dict[str, object]]],
) -> dict[str, object]:
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
        "diff_report_url": "https://socket.dev/fixture/diff?source=stream#done",
        "artifacts": artifacts,
    }


@pytest.mark.parametrize("streaming_fallback", [False, True])
def test_json_contains_real_classified_packages_without_extra_transport(
    socket_api: SocketApiFixture,
    streaming_fallback: bool,
) -> None:
    core = _core(socket_api)
    artifacts = _artifacts()
    if streaming_fallback:
        socket_api.route(
            "POST",
            "orgs/fixture-org/diff-scans/from-ids",
            SocketResponse(403, {"error": {"message": "forbidden"}}),
        )
        socket_api.route(
            "GET",
            "orgs/fixture-org/full-scans/diff",
            SocketResponse(200, _stream_response(artifacts)),
        )
    else:
        socket_api.route(
            "POST",
            "orgs/fixture-org/diff-scans/from-ids",
            SocketResponse(201, {"diff_scan": {"id": "diff-fixture"}}),
        )
        socket_api.route(
            "GET",
            "orgs/fixture-org/diff-scans/diff-fixture",
            SocketResponse(
                200,
                {
                    "diff_scan": {
                        "artifacts": artifacts,
                        "before_full_scan": {"id": "baseline-id"},
                        "after_full_scan": {"id": "new-scan-id"},
                    }
                },
            ),
        )

    comparison = core._get_package_comparison(
        "baseline-id", "new-scan-id", include_license_details=False
    )
    requests_after_comparison = len(socket_api.requests)
    report = build_socket_json_report(
        core.create_diff_report(
            comparison.added_packages,
            comparison.removed_packages,
            {"unchanged-id": comparison.packages["pypi/steady-lib@4.0.0"]},
        ),
        CliConfig(api_token="fictional-local-only", repo="fixture-repo"),
    )

    assert len(socket_api.requests) == requests_after_comparison
    assert [row["id"] for row in report["new_packages"]] == ["added-id"]
    assert [row["id"] for row in report["updated_packages"]] == ["updated-id"]
    assert [row["id"] for row in report["removed_packages"]] == ["removed-id"]
    assert [row["id"] for row in report["replaced_packages"]] == ["replaced-id"]
    assert report["new_packages"][0]["scores"] == _score()
    assert report["new_packages"][0]["url"] == (
        "https://socket.dev/pypi/package/added-lib/overview/1.0.0"
    )
    assert report["updated_packages"][0]["purl"] == "@fictional/updated-lib@2.0.0"
    assert report["updated_packages"][0]["url"] == (
        "https://socket.dev/npm/package/@fictional/updated-lib/overview/2.0.0"
    )
    assert report["removed_packages"][0]["scores"] == {}
    assert report["new_alerts"] == []
    comparison_requests = socket_api.requests[1:]
    if streaming_fallback:
        assert [request.path for request in comparison_requests] == [
            "orgs/fixture-org/diff-scans/from-ids",
            "orgs/fixture-org/full-scans/diff",
        ]
        assert comparison_requests[1].query == {
            "before": ["baseline-id"],
            "after": ["new-scan-id"],
            "include_license_details": ["false"],
        }
    else:
        assert [request.path for request in comparison_requests] == [
            "orgs/fixture-org/diff-scans/from-ids",
            "orgs/fixture-org/diff-scans/diff-fixture",
        ]
        assert comparison_requests[1].query == {
            "cached": ["true"],
            "omit_unchanged": ["true"],
        }

    all_packages = core.create_diff_report(
        comparison.added_packages,
        comparison.removed_packages,
        {"unchanged-id": comparison.packages["pypi/steady-lib@4.0.0"]},
        direct_only=False,
    )
    assert [row.id for row in all_packages.new_packages] == [
        "added-id",
        "transitive-id",
    ]
    transitive_report = build_socket_json_report(
        all_packages,
        CliConfig(api_token="fictional-local-only", repo="fixture-repo"),
    )
    assert [row["id"] for row in transitive_report["new_packages"]] == [
        "added-id",
        "transitive-id",
    ]


def test_no_run_keeps_change_lists_empty_without_scan_requests(
    socket_api: SocketApiFixture,
) -> None:
    core = _core(socket_api)
    request_count_after_setup = len(socket_api.requests)

    result = core.create_new_diff(
        [], FullScanParams(repo="fixture-repo"), no_change=True
    )
    report = build_socket_json_report(
        result,
        CliConfig(api_token="fictional-local-only", repo="fixture-repo"),
    )

    assert len(socket_api.requests) == request_count_after_setup
    assert result.id == "NO_DIFF_RAN"
    assert report["full_scan_id"] == "NO_DIFF_RAN"
    assert report["new_packages"] == []
    assert report["updated_packages"] == []
    assert report["removed_packages"] == []
    assert report["replaced_packages"] == []


def test_full_scan_keeps_change_lists_empty(
    socket_api: SocketApiFixture,
    tmp_path,
) -> None:
    core = _core(socket_api)
    socket_api.route(
        "POST",
        "orgs/fixture-org/full-scans",
        SocketResponse(
            201,
            {
                "id": "inventory-scan-id",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "organization_id": "org-fixture",
                "repository_id": "repo-fixture",
                "branch": "main",
                "html_report_url": "https://socket.dev/scan/inventory-scan-id",
            },
        ),
    )
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("fictional-package==1.0.0\n")

    result = core.create_full_scan_with_report_url(
        [str(tmp_path)],
        FullScanParams(repo="fixture-repo", org_slug="fixture-org", branch="main"),
        explicit_files=[str(manifest)],
    )
    report = build_socket_json_report(
        result,
        CliConfig(api_token="fictional-local-only", repo="fixture-repo"),
    )

    assert result.id == "inventory-scan-id"
    assert report["new_scan_id"] == "inventory-scan-id"
    assert report["new_packages"] == []
    assert report["updated_packages"] == []
    assert report["removed_packages"] == []
    assert report["replaced_packages"] == []
