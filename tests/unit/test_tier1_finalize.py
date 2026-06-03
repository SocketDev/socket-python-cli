"""Tests for tier1 reachability finalize retry/backoff (G11, Node parity)."""
import json
from unittest.mock import MagicMock

import pytest

from socketsecurity.core import TIER1_FINALIZE_MAX_ATTEMPTS, Core


@pytest.fixture
def core_with_mock_sdk():
    # Build a Core without running org setup; we only exercise finalize_tier1_scan.
    core = Core.__new__(Core)
    core.sdk = MagicMock()
    return core


@pytest.fixture
def facts_file(tmp_path):
    path = tmp_path / ".socket.facts.json"
    path.write_text(json.dumps({"tier1ReachabilityScanId": "tier1-abc"}), encoding="utf-8")
    return str(path)


@pytest.fixture(autouse=True)
def no_sleep(mocker):
    return mocker.patch("socketsecurity.core.time.sleep")


def test_finalize_succeeds_first_try(core_with_mock_sdk, facts_file, no_sleep):
    core_with_mock_sdk.sdk.fullscans.finalize_tier1.return_value = True

    assert core_with_mock_sdk.finalize_tier1_scan("full-1", facts_file) is True
    assert core_with_mock_sdk.sdk.fullscans.finalize_tier1.call_count == 1
    no_sleep.assert_not_called()


def test_finalize_retries_then_succeeds(core_with_mock_sdk, facts_file, no_sleep):
    core_with_mock_sdk.sdk.fullscans.finalize_tier1.side_effect = [
        Exception("transient"),
        Exception("transient"),
        True,
    ]

    assert core_with_mock_sdk.finalize_tier1_scan("full-1", facts_file) is True
    assert core_with_mock_sdk.sdk.fullscans.finalize_tier1.call_count == 3
    assert no_sleep.call_count == 2  # backoff between the 3 attempts


def test_finalize_exhausts_on_persistent_exception(core_with_mock_sdk, facts_file, no_sleep):
    core_with_mock_sdk.sdk.fullscans.finalize_tier1.side_effect = Exception("down")

    # Never raises; returns False after exhausting attempts.
    assert core_with_mock_sdk.finalize_tier1_scan("full-1", facts_file) is False
    assert core_with_mock_sdk.sdk.fullscans.finalize_tier1.call_count == TIER1_FINALIZE_MAX_ATTEMPTS


def test_finalize_exhausts_on_persistent_falsy(core_with_mock_sdk, facts_file, no_sleep):
    core_with_mock_sdk.sdk.fullscans.finalize_tier1.return_value = False

    assert core_with_mock_sdk.finalize_tier1_scan("full-1", facts_file) is False
    assert core_with_mock_sdk.sdk.fullscans.finalize_tier1.call_count == TIER1_FINALIZE_MAX_ATTEMPTS


def test_finalize_returns_false_when_no_scan_id(core_with_mock_sdk, tmp_path):
    path = tmp_path / ".socket.facts.json"
    path.write_text(json.dumps({"components": []}), encoding="utf-8")

    assert core_with_mock_sdk.finalize_tier1_scan("full-1", str(path)) is False
    core_with_mock_sdk.sdk.fullscans.finalize_tier1.assert_not_called()
