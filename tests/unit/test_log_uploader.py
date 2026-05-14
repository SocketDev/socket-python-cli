import json
import logging
import time
from unittest.mock import Mock

import pytest

from socketsecurity.core.cli_client import CliClient
from socketsecurity.core.exceptions import APIFailure
from socketsecurity.core.log_uploader import (
    BatchedLogUploader,
    UploadingLogHandler,
)
from socketsecurity.core.socket_config import SocketConfig


@pytest.fixture
def config():
    return SocketConfig(api_key="k", timeout=30)


def test_add_buffers_until_flush():
    client = Mock(spec=CliClient)
    u = BatchedLogUploader(client, "run-x", flush_interval=10)
    u.add({"timestamp": "t", "level": "INFO", "message": "a", "context": "c"})
    u.add({"timestamp": "t", "level": "INFO", "message": "b", "context": "c"})
    client.request.assert_not_called()
    assert len(u._buf) == 2


def test_flush_posts_batch_and_clears_buffer():
    client = Mock(spec=CliClient)
    u = BatchedLogUploader(client, "run-y", flush_interval=10)
    u.add({"timestamp": "t", "level": "INFO", "message": "a", "context": "c"})
    u.add({"timestamp": "t", "level": "WARN", "message": "b", "context": "c"})

    u._flush()

    args, kwargs = client.request.call_args
    assert kwargs["path"] == "python-cli-runs/run-y/logs"
    assert kwargs["method"] == "POST"
    body = json.loads(kwargs["payload"])
    assert len(body["logs"]) == 2
    assert body["logs"][0]["message"] == "a"
    assert u._buf == []


def test_flush_skips_empty_buffer():
    client = Mock(spec=CliClient)
    u = BatchedLogUploader(client, "run-z", flush_interval=10)
    u._flush()
    client.request.assert_not_called()


def test_flush_swallows_api_failure_and_drops_batch():
    client = Mock(spec=CliClient)
    client.request.side_effect = APIFailure("net down")
    u = BatchedLogUploader(client, "run-e", flush_interval=10)
    u.add({"timestamp": "t", "level": "INFO", "message": "x", "context": "c"})

    u._flush()  # must not raise
    assert u._buf == []  # batch is dropped, not retried


def test_stop_drains_remaining_buffer():
    client = Mock(spec=CliClient)
    u = BatchedLogUploader(client, "run-d", flush_interval=10)
    u.start()
    u.add({"timestamp": "t", "level": "INFO", "message": "tail", "context": "c"})
    u.stop(timeout=2.0)

    assert client.request.called
    body = json.loads(client.request.call_args.kwargs["payload"])
    assert body["logs"][-1]["message"] == "tail"


def test_handler_emit_enqueues_record(caplog):
    client = Mock(spec=CliClient)
    u = BatchedLogUploader(client, "run-h", flush_interval=10)
    h = UploadingLogHandler(u)

    rec = logging.LogRecord(
        name="socketcli", level=logging.WARNING, pathname=__file__,
        lineno=1, msg="watch out", args=(), exc_info=None,
    )
    h.emit(rec)

    assert len(u._buf) == 1
    e = u._buf[0]
    assert e["level"] == "WARN"
    assert e["message"] == "watch out"
    assert e["context"] == "socket-python-cli"


def test_handler_skips_during_active_flush():
    client = Mock(spec=CliClient)
    u = BatchedLogUploader(client, "run-g", flush_interval=10)
    h = UploadingLogHandler(u)

    captured = {}

    def fake_request(**kwargs):
        rec = logging.LogRecord(
            name="socketdev", level=logging.ERROR, pathname=__file__,
            lineno=1, msg="recursive!", args=(), exc_info=None,
        )
        h.emit(rec)
        captured["buf_len_during_flush"] = len(u._buf)
        return Mock()

    client.request.side_effect = fake_request
    u.add({"timestamp": "t", "level": "INFO", "message": "real", "context": "c"})
    u._flush()

    assert captured["buf_len_during_flush"] == 0  # recursive emit was skipped
    assert u._buf == []


def test_levels_map_correctly():
    client = Mock(spec=CliClient)
    u = BatchedLogUploader(client, "run-l", flush_interval=10)
    h = UploadingLogHandler(u)

    for py_level, expected in [
        (logging.DEBUG, "DEBUG"),
        (logging.INFO, "INFO"),
        (logging.WARNING, "WARN"),
        (logging.ERROR, "ERROR"),
        (logging.CRITICAL, "ERROR"),
    ]:
        rec = logging.LogRecord(
            name="t", level=py_level, pathname=__file__,
            lineno=1, msg="m", args=(), exc_info=None,
        )
        h.emit(rec)

    levels = [e["level"] for e in u._buf]
    assert levels == ["DEBUG", "INFO", "WARN", "ERROR", "ERROR"]


def test_run_thread_flushes_periodically_then_exits():
    client = Mock(spec=CliClient)
    u = BatchedLogUploader(client, "run-t", flush_interval=0.05)
    u.add({"timestamp": "t", "level": "INFO", "message": "first", "context": "c"})
    u.start()
    time.sleep(0.2)  # allow at least one flush tick
    u.stop(timeout=1.0)
    assert client.request.called
