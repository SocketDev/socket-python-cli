"""Package-change JSON transport coverage across real Core and SDK paths."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

import pytest
from socketdev import socketdev
from socketdev.fullscans import FullScanParams

from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.classes import Package
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
    ecosystem: str | None = None,
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
        "type": ecosystem or ("npm" if namespace else "pypi"),
        "name": name,
        "version": version,
        "alerts": [],
        "licenseDetails": [],
        "author": ["Fixture Author"],
        "head" if change_type in ("added", "updated", "unchanged") else "base": [
            reference
        ],
    }
    if namespace is not None:
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


def _namespace_identity_artifacts() -> dict[str, list[dict[str, object]]]:
    def artifact(
        artifact_id: str,
        change_type: str,
        ecosystem: str,
        namespace: str | None,
        name: str,
        version: str,
        quality: float,
        *,
        direct: bool = True,
        parent_id: str | None = None,
    ) -> dict[str, object]:
        score = _score()
        score["quality"] = quality
        return _artifact(
            artifact_id,
            change_type,
            name,
            version,
            direct=direct,
            namespace=namespace,
            ecosystem=ecosystem,
            score=score,
            parent_id=parent_id,
        )

    return {
        "added": [
            artifact("added-one", "added", "npm", "@one", "widget", "1.0.0", 0.1),
            artifact("added-two", "added", "npm", "@two", "widget", "1.0.0", 0.2),
            artifact("added-duplicate", "added", "npm", "@one", "widget", "1.0.0", 0.3),
            artifact("added-unscoped", "added", "npm", None, "widget", "1.0.0", 0.4),
            artifact("added-pypi", "added", "pypi", None, "widget", "1.0.0", 0.5),
            artifact(
                "child-transitive",
                "added",
                "npm",
                "@child",
                "leaf",
                "2.0.0",
                0.6,
                direct=False,
                parent_id="added-one",
            ),
            artifact("child-direct", "added", "npm", "@child", "leaf", "2.0.0", 0.7),
        ],
        "updated": [
            artifact(
                "updated-one", "updated", "maven", "com.one", "widget", "3.0.0", 0.1
            ),
            artifact(
                "updated-two", "updated", "maven", "com.two", "widget", "3.0.0", 0.2
            ),
            artifact(
                "updated-duplicate",
                "updated",
                "maven",
                "com.one",
                "widget",
                "3.0.0",
                0.3,
            ),
        ],
        "removed": [
            artifact(
                "removed-cross-bucket", "removed", "npm", "@one", "widget", "1.0.0", 0.8
            ),
            artifact("removed-one", "removed", "npm", "@one", "retired", "4.0.0", 0.1),
            artifact("removed-two", "removed", "npm", "@two", "retired", "4.0.0", 0.2),
            artifact(
                "removed-duplicate", "removed", "npm", "@one", "retired", "4.0.0", 0.3
            ),
        ],
        "replaced": [
            artifact(
                "replaced-one", "replaced", "maven", "com.one", "retired", "5.0.0", 0.1
            ),
            artifact(
                "replaced-two", "replaced", "maven", "com.two", "retired", "5.0.0", 0.2
            ),
            artifact(
                "replaced-duplicate",
                "replaced",
                "maven",
                "com.one",
                "retired",
                "5.0.0",
                0.3,
            ),
        ],
        "unchanged": [],
    }


@pytest.mark.parametrize("streaming_fallback", [False, True])
def test_package_change_identity_keeps_namespace_and_bucket_boundaries(
    socket_api: SocketApiFixture,
    streaming_fallback: bool,
) -> None:
    core = _core(socket_api)
    artifacts = _namespace_identity_artifacts()
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
            SocketResponse(201, {"diff_scan": {"id": "diff-namespace-fixture"}}),
        )
        socket_api.route(
            "GET",
            "orgs/fixture-org/diff-scans/diff-namespace-fixture",
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
    request_count = len(socket_api.requests)
    diff = core.create_diff_report(
        comparison.added_packages,
        comparison.removed_packages,
        {},
    )
    report = build_socket_json_report(
        diff,
        CliConfig(api_token="fictional-local-only", repo="fixture-repo"),
    )

    expected_ids = {
        "new_packages": [
            "added-one",
            "added-two",
            "added-unscoped",
            "added-pypi",
            "child-direct",
        ],
        "updated_packages": ["updated-one", "updated-two"],
        "removed_packages": [
            "removed-cross-bucket",
            "removed-one",
            "removed-two",
        ],
        "replaced_packages": ["replaced-one", "replaced-two"],
    }
    assert {
        "new_packages": [package.id for package in diff.new_packages],
        "updated_packages": [package.id for package in diff.updated_packages],
        "removed_packages": [package.id for package in diff.removed_packages],
        "replaced_packages": [package.id for package in diff.replaced_packages],
    } == expected_ids
    assert {
        key: [row["id"] for row in report[key]] for key in expected_ids
    } == expected_ids

    new_rows = {row["id"]: row for row in report["new_packages"]}
    assert new_rows["added-one"]["purl"] == "@one/widget@1.0.0"
    assert new_rows["added-two"]["purl"] == "@two/widget@1.0.0"
    assert new_rows["added-unscoped"]["purl"] == "widget@1.0.0"
    assert new_rows["added-pypi"]["ecosystem"] == "pypi"
    assert new_rows["added-one"]["url"] == (
        "https://socket.dev/npm/package/@one/widget/overview/1.0.0"
    )
    assert new_rows["added-two"]["url"] == (
        "https://socket.dev/npm/package/@two/widget/overview/1.0.0"
    )
    assert new_rows["added-one"]["scores"]["quality"] == 0.1
    assert new_rows["added-two"]["scores"]["quality"] == 0.2
    assert "previousVersion" not in new_rows["added-one"]

    updated_rows = {row["id"]: row for row in report["updated_packages"]}
    assert updated_rows["updated-one"]["purl"] == "com.one/widget@3.0.0"
    assert updated_rows["updated-two"]["purl"] == "com.two/widget@3.0.0"
    assert updated_rows["updated-one"]["url"] == (
        "https://socket.dev/maven/package/com.one/widget/overview/3.0.0"
    )
    assert updated_rows["updated-two"]["url"] == (
        "https://socket.dev/maven/package/com.two/widget/overview/3.0.0"
    )
    assert updated_rows["updated-one"]["scores"]["quality"] == 0.1
    assert updated_rows["updated-two"]["scores"]["quality"] == 0.2

    removed_rows = {row["id"]: row for row in report["removed_packages"]}
    assert removed_rows["removed-one"]["purl"] == "@one/retired@4.0.0"
    assert removed_rows["removed-two"]["purl"] == "@two/retired@4.0.0"
    assert removed_rows["removed-one"]["url"] == (
        "https://socket.dev/npm/package/@one/retired/overview/4.0.0"
    )
    assert removed_rows["removed-two"]["url"] == (
        "https://socket.dev/npm/package/@two/retired/overview/4.0.0"
    )
    assert removed_rows["removed-one"]["scores"]["quality"] == 0.1
    assert removed_rows["removed-two"]["scores"]["quality"] == 0.2

    replaced_rows = {row["id"]: row for row in report["replaced_packages"]}
    assert replaced_rows["replaced-one"]["purl"] == "com.one/retired@5.0.0"
    assert replaced_rows["replaced-two"]["purl"] == "com.two/retired@5.0.0"
    assert replaced_rows["replaced-one"]["url"] == (
        "https://socket.dev/maven/package/com.one/retired/overview/5.0.0"
    )
    assert replaced_rows["replaced-two"]["url"] == (
        "https://socket.dev/maven/package/com.two/retired/overview/5.0.0"
    )
    assert replaced_rows["replaced-one"]["scores"]["quality"] == 0.1
    assert replaced_rows["replaced-two"]["scores"]["quality"] == 0.2

    assert report["new_alerts"] == []
    assert set(report) == {
        "scan_failed",
        "new_alerts",
        "full_scan_id",
        "diff_url",
        "report_url",
        "diff_scan_id",
        "old_scan_id",
        "new_scan_id",
        "old_scan_url",
        "new_scan_url",
        "repo",
        "branch",
        "commit_sha",
        "legal_mode",
        "new_packages",
        "updated_packages",
        "removed_packages",
        "replaced_packages",
    }
    assert len(socket_api.requests) == request_count

    direct_only_false = core.create_diff_report(
        comparison.added_packages,
        comparison.removed_packages,
        {},
        direct_only=False,
    )
    assert [package.id for package in direct_only_false.new_packages] == [
        "added-one",
        "added-two",
        "added-unscoped",
        "added-pypi",
        "child-transitive",
    ]


def test_package_change_identity_treats_missing_and_empty_namespace_equally(
    socket_api: SocketApiFixture,
) -> None:
    core = _core(socket_api)
    package = Package(
        id="source",
        name="widget",
        version="1.0.0",
        type="npm",
        score={},
        alerts=[],
        direct=True,
        manifestFiles=[{"file": "package.json"}],
    )
    missing_namespace = replace(package, id="missing-namespace", namespace=None)
    empty_namespace = replace(package, id="empty-namespace", namespace="")

    diff = core.create_diff_report(
        {
            missing_namespace.id: missing_namespace,
            empty_namespace.id: empty_namespace,
        },
        {},
    )

    assert [package.id for package in diff.new_packages] == ["missing-namespace"]


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
