"""Tests for the full-scan upload retry on transient gateway/connection failures.

A `POST /orgs/<org>/full-scans` upload can fail transiently (an HTTP 502/503/504/408, a
dropped or reset connection, or a timeout) without the server having created the scan.
`Core.create_full_scan` retries the failures the SDK classifies as transient
(`APIFailure.is_transient_error()`, socketdev>=3.3.0); these tests cover the retry
decision, the loop bounds, and that the temporary brotli-compressed facts files survive
until every attempt has finished.
"""

import logging
from unittest.mock import MagicMock

import pytest
from socketdev.exceptions import (
    APIAccessDenied,
    APIBadGateway,
    APIConnectionError,
    APIFailure,
    APIResourceNotFound,
    APITimeout,
)
from socketdev.fullscans import FullScanMetadata

from socketsecurity.core import (
    FULL_SCAN_UPLOAD_MAX_ATTEMPTS,
    SOCKET_FACTS_BROTLI_FILENAME,
    SOCKET_FACTS_FILENAME,
    Core,
)


def _success_response():
    metadata = FullScanMetadata(
        id="scan-1",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
        organization_id="org-1",
        repository_id="repo-1",
        branch="main",
        html_report_url="https://socket.dev/report",
    )
    response = MagicMock()
    response.success = True
    response.data = metadata
    return response


# Catch-all APIFailure as the SDK raises it for statuses without a dedicated class
# (socketdev/core/api.py); the recorded status_code drives is_transient_error().
def _catch_all_failure(status_code: int) -> APIFailure:
    return APIFailure(
        f"Bad Request: HTTP original_status_code:{status_code}\n"
        f"Path: https://api.socket.dev/v0/orgs/org/full-scans\n\n"
        f"Headers:\ncf-ray: abc123",
        status_code=status_code,
    )


@pytest.fixture
def core_with_mock_sdk():
    # Build a Core without running org setup; we only exercise create_full_scan.
    core = Core.__new__(Core)
    core.sdk = MagicMock()
    core.cli_config = None  # skip the tier1 finalize branch
    return core


@pytest.fixture(autouse=True)
def no_sleep(mocker):
    return mocker.patch("socketsecurity.core.time.sleep")


def test_upload_succeeds_first_try(core_with_mock_sdk, tmp_path, no_sleep):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    core_with_mock_sdk.sdk.fullscans.post.return_value = _success_response()

    full_scan = core_with_mock_sdk.create_full_scan([str(manifest)], MagicMock())

    assert full_scan.id == "scan-1"
    assert core_with_mock_sdk.sdk.fullscans.post.call_count == 1
    no_sleep.assert_not_called()


def test_upload_retries_on_502_then_succeeds(
    core_with_mock_sdk, tmp_path, no_sleep, caplog
):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    core_with_mock_sdk.sdk.fullscans.post.side_effect = [
        APIBadGateway(),
        APIBadGateway(),
        _success_response(),
    ]

    with caplog.at_level(logging.WARNING, logger="socketdev"):
        full_scan = core_with_mock_sdk.create_full_scan([str(manifest)], MagicMock())

    assert full_scan.id == "scan-1"
    assert core_with_mock_sdk.sdk.fullscans.post.call_count == 3
    assert no_sleep.call_count == 2  # waits before attempts 2 and 3
    retry_warnings = [r for r in caplog.records if "retrying in" in r.message]
    assert len(retry_warnings) == 2
    assert "APIBadGateway" in retry_warnings[0].message
    assert f"(attempt 2/{FULL_SCAN_UPLOAD_MAX_ATTEMPTS})" in retry_warnings[0].message


def test_upload_raises_after_exhausting_attempts(
    core_with_mock_sdk, tmp_path, no_sleep
):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    core_with_mock_sdk.sdk.fullscans.post.side_effect = APIBadGateway()

    with pytest.raises(APIBadGateway):
        core_with_mock_sdk.create_full_scan([str(manifest)], MagicMock())

    assert (
        core_with_mock_sdk.sdk.fullscans.post.call_count
        == FULL_SCAN_UPLOAD_MAX_ATTEMPTS
    )


@pytest.mark.parametrize("status_code", [408, 503, 504])
def test_upload_retries_on_catch_all_transient_statuses(
    core_with_mock_sdk, tmp_path, no_sleep, status_code
):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    core_with_mock_sdk.sdk.fullscans.post.side_effect = [
        _catch_all_failure(status_code),
        _success_response(),
    ]

    full_scan = core_with_mock_sdk.create_full_scan([str(manifest)], MagicMock())

    assert full_scan.id == "scan-1"
    assert core_with_mock_sdk.sdk.fullscans.post.call_count == 2


@pytest.mark.parametrize("error_class", [APIConnectionError, APITimeout])
def test_upload_retries_on_connection_level_errors(
    core_with_mock_sdk, tmp_path, no_sleep, error_class
):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    core_with_mock_sdk.sdk.fullscans.post.side_effect = [
        error_class(),
        _success_response(),
    ]

    full_scan = core_with_mock_sdk.create_full_scan([str(manifest)], MagicMock())

    assert full_scan.id == "scan-1"
    assert core_with_mock_sdk.sdk.fullscans.post.call_count == 2


def test_upload_does_not_retry_on_400(core_with_mock_sdk, tmp_path, no_sleep):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    core_with_mock_sdk.sdk.fullscans.post.side_effect = _catch_all_failure(400)

    with pytest.raises(APIFailure):
        core_with_mock_sdk.create_full_scan([str(manifest)], MagicMock())

    assert core_with_mock_sdk.sdk.fullscans.post.call_count == 1
    no_sleep.assert_not_called()


@pytest.mark.parametrize(
    "error_class,status_code", [(APIAccessDenied, 401), (APIResourceNotFound, 404)]
)
def test_upload_does_not_retry_on_dedicated_4xx_classes(
    core_with_mock_sdk, tmp_path, no_sleep, error_class, status_code
):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    core_with_mock_sdk.sdk.fullscans.post.side_effect = error_class(
        status_code=status_code
    )

    with pytest.raises(error_class):
        core_with_mock_sdk.create_full_scan([str(manifest)], MagicMock())

    assert core_with_mock_sdk.sdk.fullscans.post.call_count == 1
    no_sleep.assert_not_called()


def test_upload_does_not_retry_on_error_payload(core_with_mock_sdk, tmp_path, no_sleep):
    # A response that came back but reports failure (res.success False) is not transient.
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    failed = MagicMock()
    failed.success = False
    failed.message = "tarball too large"
    failed.status = 200
    core_with_mock_sdk.sdk.fullscans.post.return_value = failed

    with pytest.raises(Exception, match="tarball too large"):
        core_with_mock_sdk.create_full_scan([str(manifest)], MagicMock())

    assert core_with_mock_sdk.sdk.fullscans.post.call_count == 1
    no_sleep.assert_not_called()


def test_temp_br_file_survives_retries_and_is_cleaned_after(
    core_with_mock_sdk, tmp_path, no_sleep
):
    # The brotli-compressed facts sibling must stay on disk across every retry attempt
    # (the SDK re-reads it per call) and only be deleted once all attempts finished.
    facts = tmp_path / SOCKET_FACTS_FILENAME
    facts.write_text('{"components": []}')
    compressed = tmp_path / SOCKET_FACTS_BROTLI_FILENAME
    br_present_per_attempt = []

    def post_side_effect(upload_files, *args, **kwargs):
        br_present_per_attempt.append(compressed.is_file())
        assert str(compressed) in upload_files
        if len(br_present_per_attempt) < 3:
            raise APIBadGateway()
        return _success_response()

    core_with_mock_sdk.sdk.fullscans.post.side_effect = post_side_effect

    full_scan = core_with_mock_sdk.create_full_scan([str(facts)], MagicMock())

    assert full_scan.id == "scan-1"
    assert br_present_per_attempt == [True, True, True]
    assert not compressed.exists()  # cleaned up after the attempts finished
    assert facts.is_file()  # the original facts file is never touched


def test_temp_br_file_cleaned_after_exhausted_retries(
    core_with_mock_sdk, tmp_path, no_sleep
):
    facts = tmp_path / SOCKET_FACTS_FILENAME
    facts.write_text('{"components": []}')
    compressed = tmp_path / SOCKET_FACTS_BROTLI_FILENAME
    core_with_mock_sdk.sdk.fullscans.post.side_effect = APIBadGateway()

    with pytest.raises(APIBadGateway):
        core_with_mock_sdk.create_full_scan([str(facts)], MagicMock())

    assert (
        core_with_mock_sdk.sdk.fullscans.post.call_count
        == FULL_SCAN_UPLOAD_MAX_ATTEMPTS
    )
    assert not compressed.exists()


class _StubFailure(APIFailure):
    """An APIFailure whose transience is fixed, regardless of class or status code."""

    def __init__(self, transient: bool):
        super().__init__("stub failure")
        self._transient = transient

    def is_transient_error(self) -> bool:
        return self._transient


@pytest.mark.parametrize("transient,expected_calls", [(True, 2), (False, 1)])
def test_retry_decision_delegates_to_sdk_classification(
    core_with_mock_sdk, tmp_path, no_sleep, transient, expected_calls
):
    # The CLI encodes no knowledge of the SDK's exception hierarchy or status codes:
    # the retry decision is exactly APIFailure.is_transient_error(). (The transient /
    # non-transient truth table itself is tested in the SDK, next to the code that
    # raises the exceptions.)
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    core_with_mock_sdk.sdk.fullscans.post.side_effect = [
        _StubFailure(transient),
        _success_response(),
    ]

    if transient:
        full_scan = core_with_mock_sdk.create_full_scan([str(manifest)], MagicMock())
        assert full_scan.id == "scan-1"
    else:
        with pytest.raises(_StubFailure):
            core_with_mock_sdk.create_full_scan([str(manifest)], MagicMock())

    assert core_with_mock_sdk.sdk.fullscans.post.call_count == expected_calls
