"""Tests for the diff-scans polling scan comparison.

The comparison must never hold an idle connection open: it creates a diff-scan
resource and polls the cached endpoint (202 while processing, 200 when ready),
falling back to the legacy streaming diff if the new flow is unavailable.
"""
import pytest
from socketdev.exceptions import APIConnectionError, APIFailure

import socketsecurity.core as core_module
from socketsecurity.core import Core
from socketsecurity.core.socket_config import SocketConfig


@pytest.fixture
def core(mock_sdk_with_responses):
    config = SocketConfig(api_key="test_key")
    return Core(config=config, sdk=mock_sdk_with_responses)


@pytest.fixture
def no_sleep(mocker):
    return mocker.patch("socketsecurity.core.time.sleep")


def test_polls_until_diff_scan_ready(core, diff_scan_get_response, no_sleep):
    """202 processing responses are polled through until the 200 result arrives."""
    processing = {"status": "processing", "id": "diff-scan-123"}
    core.sdk.diffscans.get.side_effect = [processing, processing, diff_scan_get_response]

    artifacts = core.get_diff_scan_artifacts("head", "new")

    assert core.sdk.diffscans.get.call_count == 3
    assert no_sleep.call_count == 2  # slept between polls, never during them
    assert len(artifacts.added) > 0


def test_poll_interval_backs_off(core, diff_scan_get_response, no_sleep, monkeypatch):
    """The poll interval grows toward the max so long comparisons stay quota-friendly."""
    monkeypatch.setattr(core_module, "DIFF_SCAN_POLL_INITIAL_INTERVAL_SECONDS", 4.0)
    monkeypatch.setattr(core_module, "DIFF_SCAN_POLL_MAX_INTERVAL_SECONDS", 10.0)
    processing = {"status": "processing", "id": "diff-scan-123"}
    core.sdk.diffscans.get.side_effect = [processing] * 4 + [diff_scan_get_response]

    core.get_diff_scan_artifacts("head", "new")

    waits = [call.args[0] for call in no_sleep.call_args_list]
    assert waits == [4.0, 6.0, 9.0, 10.0]  # 1.5x backoff, capped at the max


def test_transient_poll_error_is_retried(core, diff_scan_get_response, no_sleep):
    """A dropped poll doesn't abandon the flow - the diff keeps computing server-side."""
    core.sdk.diffscans.get.side_effect = [APIConnectionError("reset"), diff_scan_get_response]

    artifacts = core.get_diff_scan_artifacts("head", "new")

    assert core.sdk.diffscans.get.call_count == 2
    assert len(artifacts.added) > 0


def test_non_transient_poll_error_raises(core, no_sleep):
    """Deterministic API errors (e.g. 403 missing scopes) propagate to the caller."""
    core.sdk.diffscans.get.side_effect = APIFailure("forbidden", status_code=403)

    with pytest.raises(APIFailure):
        core.get_diff_scan_artifacts("head", "new")


def test_poll_timeout_raises(core, no_sleep, monkeypatch):
    """A diff scan that never completes hits the polling backstop."""
    monkeypatch.setattr(core_module, "DIFF_SCAN_POLL_TIMEOUT_SECONDS", 0.0)
    core.sdk.diffscans.get.return_value = {"status": "processing", "id": "diff-scan-123"}

    with pytest.raises(Exception, match="Timed out waiting for diff scan"):
        core.get_diff_scan_artifacts("head", "new")


def test_duplicate_conflict_uses_cached_polling(core, diff_scan_get_response):
    """A duplicate is resolved explicitly so the SDK cannot follow an uncached redirect."""
    core.sdk.diffscans.create_from_ids.side_effect = APIFailure(
        "duplicate", status_code=409
    )
    core.sdk.diffscans.list.return_value = {
        "results": [{"id": "existing-diff-scan"}],
    }

    artifacts = core.get_diff_scan_artifacts("head", "new")

    create_params = core.sdk.diffscans.create_from_ids.call_args.args[1]
    assert "on_duplicate" not in create_params
    core.sdk.diffscans.list.assert_called_once_with(
        core.config.org_slug,
        params={
            "before_full_scan_id": "head",
            "after_full_scan_id": "new",
            "per_page": 1,
        },
    )
    core.sdk.diffscans.get.assert_called_once_with(
        core.config.org_slug,
        "existing-diff-scan",
        params={"cached": "true"},
    )
    assert len(artifacts.added) > 0


def test_eager_create_artifacts_do_not_bypass_filtered_get(core, diff_scan_get_response):
    """Unexpected create artifacts are ignored so the filtered GET remains canonical."""
    from types import SimpleNamespace

    core.cli_config = SimpleNamespace(
        strict_blocking=False,
        enable_gitlab_security=False,
        generate_license=False,
        legal_format="socket",
    )
    core.sdk.diffscans.create_from_ids.return_value = {
        "diff_scan": {
            "id": "diff-scan-123",
            "artifacts": diff_scan_get_response["diff_scan"]["artifacts"],
        }
    }

    core.get_diff_scan_artifacts("head", "new")

    core.sdk.diffscans.get.assert_called_once_with(
        core.config.org_slug,
        "diff-scan-123",
        params={"cached": "true", "omit_unchanged": "true"},
    )


def test_eager_list_artifacts_do_not_bypass_filtered_get(core, diff_scan_get_response):
    """Unexpected duplicate-list artifacts cannot skip the filtered GET either."""
    from types import SimpleNamespace

    core.cli_config = SimpleNamespace(
        strict_blocking=False,
        enable_gitlab_security=False,
        generate_license=False,
        legal_format="socket",
    )
    core.sdk.diffscans.create_from_ids.side_effect = APIFailure(
        "duplicate", status_code=409
    )
    core.sdk.diffscans.list.return_value = {
        "results": [
            {
                "id": "existing-diff-scan",
                "artifacts": diff_scan_get_response["diff_scan"]["artifacts"],
            }
        ],
    }

    core.get_diff_scan_artifacts("head", "new")

    core.sdk.diffscans.get.assert_called_once_with(
        core.config.org_slug,
        "existing-diff-scan",
        params={"cached": "true", "omit_unchanged": "true"},
    )


def test_fallback_to_streaming_diff_on_failure(core):
    """If the diff-scans flow fails (e.g. token missing the diff-scans scopes),
    the comparison falls back to the legacy streaming diff transparently."""
    core.sdk.diffscans.create_from_ids.side_effect = APIFailure("forbidden", status_code=403)

    added, removed, all_packages = core.get_added_and_removed_packages("head", "new")

    core.sdk.fullscans.stream_diff.assert_called_once_with(
        core.config.org_slug,
        "head",
        "new",
        use_types=True,
        include_license_details="false",
    )
    assert "dp3" in added
    assert "dp2" in removed


def test_completion_log_reports_id_polls_and_final_wait(
        core, diff_scan_get_response, no_sleep, caplog, monkeypatch
):
    """The completion log must let a CI log separate backend compute time from the
    time a finished comparison sat unnoticed between polls."""
    import logging

    monkeypatch.setattr(core_module, "DIFF_SCAN_POLL_INITIAL_INTERVAL_SECONDS", 4.0)
    monkeypatch.setattr(core_module, "DIFF_SCAN_POLL_MAX_INTERVAL_SECONDS", 6.0)
    processing = {"status": "processing", "id": "diff-scan-123"}
    core.sdk.diffscans.get.side_effect = [processing, processing, diff_scan_get_response]

    with caplog.at_level(logging.INFO, logger="socketdev"):
        core.get_diff_scan_artifacts("head", "new")

    messages = [record.message for record in caplog.records]
    assert any("Diff scan created: id=" in message for message in messages)
    ready = next(message for message in messages if "Diff scan comparison ready" in message)
    assert "polls=3" in ready
    # Waits were 4s then 6s (capped); the final poll followed the 6s wait, which is
    # the upper bound on how long the result was ready before being observed.
    assert "wait_before_final_poll=6s" in ready


def test_max_poll_interval_bounds_dead_time_for_ci_budgets():
    """A finished comparison is never left unobserved longer than the max interval."""
    assert core_module.DIFF_SCAN_POLL_MAX_INTERVAL_SECONDS <= 10.0
    assert (
        core_module.DIFF_SCAN_POLL_INITIAL_INTERVAL_SECONDS
        <= core_module.DIFF_SCAN_POLL_MAX_INTERVAL_SECONDS
    )


UNCHANGED_ARTIFACT_CONSUMERS = [
    # flag name, value that makes the flag active
    ("strict_blocking", True),
    ("enable_gitlab_security", True),
    ("generate_license", True),
    ("legal_format", "fossa"),
]


@pytest.mark.parametrize(("flag", "value"), UNCHANGED_ARTIFACT_CONSUMERS)
def test_unchanged_artifacts_gating(core, diff_scan_get_response, flag, value):
    """Any output that reads unchanged artifacts must keep them in the response.

    This pins the consumer list in Core._requires_unchanged_artifacts: adding a new
    reader of diff.unchanged_alerts or diff.packages without adding it here (and to
    that method) would silently ship an empty result to that output.
    """
    from types import SimpleNamespace

    defaults = {name: (False if name != "legal_format" else "socket")
                for name, _ in UNCHANGED_ARTIFACT_CONSUMERS}
    core.cli_config = SimpleNamespace(**{**defaults, flag: value})
    core.sdk.diffscans.get.side_effect = None
    core.sdk.diffscans.get.return_value = diff_scan_get_response

    core.get_diff_scan_artifacts("head", "new")

    params = core.sdk.diffscans.get.call_args.kwargs["params"]
    assert "omit_unchanged" not in params, f"{flag}={value} still needs unchanged artifacts"


def test_unchanged_artifacts_omitted_when_no_output_reads_them(core, diff_scan_get_response):
    """With no such flag set, the ~1 KB-per-artifact unchanged half is not fetched."""
    from types import SimpleNamespace

    core.cli_config = SimpleNamespace(
        strict_blocking=False,
        enable_gitlab_security=False,
        generate_license=False,
        legal_format="socket",
    )
    core.sdk.diffscans.get.side_effect = None
    core.sdk.diffscans.get.return_value = diff_scan_get_response

    core.get_diff_scan_artifacts("head", "new")

    params = core.sdk.diffscans.get.call_args.kwargs["params"]
    assert params["cached"] == "true"
    assert params["omit_unchanged"] == "true"


def test_unknown_caller_keeps_full_payload(core, diff_scan_get_response):
    """cli_config is optional; without it, do not assume unchanged is unused."""
    core.cli_config = None
    core.sdk.diffscans.get.side_effect = None
    core.sdk.diffscans.get.return_value = diff_scan_get_response

    core.get_diff_scan_artifacts("head", "new")

    assert "omit_unchanged" not in core.sdk.diffscans.get.call_args.kwargs["params"]
