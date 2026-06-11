import logging
from unittest.mock import patch

import socketsecurity.core.streaming as streaming_mod
from socketsecurity.core.streaming import StreamingLogs, setup_streaming


def _make(**overrides):
    kwargs = dict(
        client=object(),
        cli_logger=logging.getLogger(overrides.pop("cli_name", "t-cli")),
        sdk_logger=logging.getLogger(overrides.pop("sdk_name", "t-sdk")),
        client_version="1.0",
        share_logs=True,
        decline_logs=False,
        enable_debug=False,
    )
    kwargs.update(overrides)
    return setup_streaming(**kwargs)


def test_setup_streaming_is_noop_when_register_fails():
    finalize_calls = []
    with patch("socketsecurity.core.streaming.register_cli_run", return_value=None), \
         patch("socketsecurity.core.streaming.finalize_cli_run", side_effect=lambda *a, **k: finalize_calls.append(k)):
        with _make(cli_name="t-fail-cli", sdk_name="t-fail-sdk") as streaming:
            assert isinstance(streaming, StreamingLogs)
    # No run was registered → finalize must not be called.
    assert finalize_calls == []


def test_clean_exit_reports_success():
    finalize_calls = []
    with patch("socketsecurity.core.streaming.register_cli_run", return_value="run-ok"), \
         patch("socketsecurity.core.streaming.finalize_cli_run", side_effect=lambda c, r, status, report_run_id: finalize_calls.append((status, report_run_id))), \
         patch.object(streaming_mod.BatchedLogUploader, "start"), \
         patch.object(streaming_mod.BatchedLogUploader, "stop"):
        with _make(cli_name="t-ok-cli", sdk_name="t-ok-sdk"):
            pass
    assert finalize_calls == [("success", None)]


def test_exception_reports_failure_and_propagates():
    finalize_calls = []
    with patch("socketsecurity.core.streaming.register_cli_run", return_value="run-x"), \
         patch("socketsecurity.core.streaming.finalize_cli_run", side_effect=lambda c, r, status, report_run_id: finalize_calls.append((status, report_run_id))), \
         patch.object(streaming_mod.BatchedLogUploader, "start"), \
         patch.object(streaming_mod.BatchedLogUploader, "stop"):
        raised = False
        try:
            with _make(cli_name="t-exc-cli", sdk_name="t-exc-sdk") as streaming:
                streaming.set_report_run_id("fs-1")
                raise RuntimeError("boom")
        except RuntimeError:
            raised = True
    assert raised  # exception not swallowed
    assert finalize_calls == [("failure", "fs-1")]


def test_keyboard_interrupt_reports_cancelled():
    finalize_calls = []
    with patch("socketsecurity.core.streaming.register_cli_run", return_value="run-ki"), \
         patch("socketsecurity.core.streaming.finalize_cli_run", side_effect=lambda c, r, status, report_run_id: finalize_calls.append((status, report_run_id))), \
         patch.object(streaming_mod.BatchedLogUploader, "start"), \
         patch.object(streaming_mod.BatchedLogUploader, "stop"):
        try:
            with _make(cli_name="t-ki-cli", sdk_name="t-ki-sdk"):
                raise KeyboardInterrupt
        except KeyboardInterrupt:
            pass
    assert finalize_calls == [("cancelled", None)]


def test_system_exit_zero_is_success_nonzero_is_failure():
    statuses = []
    with patch("socketsecurity.core.streaming.register_cli_run", return_value="run-sx"), \
         patch("socketsecurity.core.streaming.finalize_cli_run", side_effect=lambda c, r, status, report_run_id: statuses.append(status)), \
         patch.object(streaming_mod.BatchedLogUploader, "start"), \
         patch.object(streaming_mod.BatchedLogUploader, "stop"):
        try:
            with _make(cli_name="t-sx0-cli", sdk_name="t-sx0-sdk"):
                raise SystemExit(0)
        except SystemExit:
            pass
        try:
            with _make(cli_name="t-sx1-cli", sdk_name="t-sx1-sdk"):
                raise SystemExit(1)
        except SystemExit:
            pass
    assert statuses == ["success", "failure"]


def test_restores_logger_state_on_exit():
    cli_logger = logging.getLogger("t-restore-cli")
    sdk_logger = logging.getLogger("t-restore-sdk")
    cli_logger.setLevel(logging.WARNING)
    sdk_logger.setLevel(logging.ERROR)
    cli_logger.propagate = True
    sdk_logger.propagate = True
    handlers_before = (len(cli_logger.handlers), len(sdk_logger.handlers))

    with patch("socketsecurity.core.streaming.register_cli_run", return_value="run-r"), \
         patch("socketsecurity.core.streaming.finalize_cli_run"), \
         patch.object(streaming_mod.BatchedLogUploader, "start"), \
         patch.object(streaming_mod.BatchedLogUploader, "stop"):
        with setup_streaming(
            client=object(),
            cli_logger=cli_logger,
            sdk_logger=sdk_logger,
            client_version="1.0",
            share_logs=True,
            decline_logs=False,
            enable_debug=False,
        ):
            # Inside the with block: levels and propagate are forced.
            assert cli_logger.level == logging.DEBUG
            assert sdk_logger.level == logging.DEBUG
            assert cli_logger.propagate is False
            assert sdk_logger.propagate is False

    assert cli_logger.level == logging.WARNING
    assert sdk_logger.level == logging.ERROR
    assert cli_logger.propagate is True
    assert sdk_logger.propagate is True
    assert (len(cli_logger.handlers), len(sdk_logger.handlers)) == handlers_before
