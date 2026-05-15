import logging
from unittest.mock import patch

import pytest

import socketsecurity.core.streaming as streaming_mod
from socketsecurity.core.streaming import (
    set_report_run_id,
    set_run_status,
    setup_streaming,
)


@pytest.fixture(autouse=True)
def reset_streaming_state():
    streaming_mod._run_status = "success"
    streaming_mod._report_run_id = None
    yield
    streaming_mod._run_status = "success"
    streaming_mod._report_run_id = None


def test_setup_streaming_returns_none_when_register_fails():
    with patch("socketsecurity.core.streaming.register_cli_run", return_value=None):
        teardown = setup_streaming(
            client=object(),
            cli_logger=logging.getLogger("t-fail"),
            sdk_logger=logging.getLogger("t-fail-sdk"),
            client_version="1.0",
            enable_debug=False,
        )
    assert teardown is None


def test_teardown_finalizes_with_current_run_status():
    cli_logger = logging.getLogger("t-finalize-cli")
    sdk_logger = logging.getLogger("t-finalize-sdk")

    finalize_calls = []

    def fake_finalize(client, run_id, status="success", report_run_id=None):
        finalize_calls.append((status, report_run_id))

    with patch("socketsecurity.core.streaming.register_cli_run", return_value="run-1"), \
         patch("socketsecurity.core.streaming.finalize_cli_run", side_effect=fake_finalize), \
         patch.object(streaming_mod.BatchedLogUploader, "start"), \
         patch.object(streaming_mod.BatchedLogUploader, "stop"):
        teardown = setup_streaming(
            client=object(),
            cli_logger=cli_logger,
            sdk_logger=sdk_logger,
            client_version="1.0",
            enable_debug=False,
        )
        assert teardown is not None

        set_run_status("failure")
        set_report_run_id("fs-xyz")
        teardown()

    assert finalize_calls == [("failure", "fs-xyz")]


def test_set_run_status_default_is_success():
    cli_logger = logging.getLogger("t-default-cli")
    sdk_logger = logging.getLogger("t-default-sdk")

    finalize_calls = []

    def fake_finalize(client, run_id, status="success", report_run_id=None):
        finalize_calls.append((status, report_run_id))

    with patch("socketsecurity.core.streaming.register_cli_run", return_value="run-2"), \
         patch("socketsecurity.core.streaming.finalize_cli_run", side_effect=fake_finalize), \
         patch.object(streaming_mod.BatchedLogUploader, "start"), \
         patch.object(streaming_mod.BatchedLogUploader, "stop"):
        teardown = setup_streaming(
            client=object(),
            cli_logger=cli_logger,
            sdk_logger=sdk_logger,
            client_version="1.0",
            enable_debug=False,
        )
        teardown()

    assert finalize_calls == [("success", None)]


def test_setup_streaming_restores_logger_state_on_teardown():
    cli_logger = logging.getLogger("t-restore-cli")
    sdk_logger = logging.getLogger("t-restore-sdk")
    cli_logger.setLevel(logging.WARNING)
    sdk_logger.setLevel(logging.ERROR)
    cli_logger.propagate = True
    sdk_logger.propagate = True
    handler_count_before = (len(cli_logger.handlers), len(sdk_logger.handlers))

    with patch("socketsecurity.core.streaming.register_cli_run", return_value="run-3"), \
         patch("socketsecurity.core.streaming.finalize_cli_run"), \
         patch.object(streaming_mod.BatchedLogUploader, "start"), \
         patch.object(streaming_mod.BatchedLogUploader, "stop"):
        teardown = setup_streaming(
            client=object(),
            cli_logger=cli_logger,
            sdk_logger=sdk_logger,
            client_version="1.0",
            enable_debug=False,
        )
        # During streaming: levels and propagate are forced
        assert cli_logger.level == logging.DEBUG
        assert sdk_logger.level == logging.DEBUG
        assert cli_logger.propagate is False
        assert sdk_logger.propagate is False
        teardown()

    assert cli_logger.level == logging.WARNING
    assert sdk_logger.level == logging.ERROR
    assert cli_logger.propagate is True
    assert sdk_logger.propagate is True
    assert (len(cli_logger.handlers), len(sdk_logger.handlers)) == handler_count_before
