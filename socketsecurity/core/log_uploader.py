"""Buffer the CLI's local log records and POST them in batches to
/python-cli-runs/<run_id>/logs so the dashboard's view of a CLI run
mirrors what the user sees in their terminal.

Behavior:
- daemon thread, 5s flush
- swallow all network errors (debug log only)
- skip empty buffers
- drain on shutdown
- at-most-once semantics (failed batches dropped, not retried)

A thread-local recursion guard prevents the uploader's own request-error
log lines (emitted by `cli_client.py`'s `socketdev` logger) from being
re-enqueued during a flush.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from .cli_client import CliClient

log = logging.getLogger(__name__)

_FLUSH_GUARD = threading.local()

_MAX_BATCH_BYTES = 256 * 1024 - 1024  # depscan body cap is 256KB; reserve headroom for envelope/headers

_LEVEL_MAP = {
    logging.DEBUG: "DEBUG",
    logging.INFO: "INFO",
    logging.WARNING: "WARN",
    logging.ERROR: "ERROR",
    logging.CRITICAL: "ERROR",
}


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


class BatchedLogUploader:
    def __init__(
        self,
        client: CliClient,
        run_id: str,
        flush_interval: float = 5.0,
    ):
        self._client = client
        self._run_id = run_id
        self._flush_interval = flush_interval
        self._buf: list = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def add(self, entry: dict) -> None:
        with self._lock:
            self._buf.append(entry)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name=f"socket-log-uploader-{self._run_id[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        if self._thread is None:
            self._flush()
            return
        self._stop.set()
        self._thread.join(timeout=timeout)
        self._thread = None
        self._flush()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._flush()
            self._stop.wait(self._flush_interval)

    def _flush(self) -> None:
        with self._lock:
            if not self._buf:
                return
            entries = self._buf
            self._buf = []

        _FLUSH_GUARD.active = True
        try:
            for chunk in _chunk_by_size(entries):
                try:
                    self._client.request(
                        path=f"python-cli-runs/{self._run_id}/logs",
                        method="POST",
                        payload=json.dumps({"logs": chunk}),
                    )
                except Exception as e:
                    log.debug(f"log upload failed (swallowed, {len(chunk)} entries dropped): {e}")
        finally:
            _FLUSH_GUARD.active = False


def _chunk_by_size(entries: list) -> list:
    """Split entries into chunks that each serialize to <= _MAX_BATCH_BYTES.
    Single entries that exceed the cap are dropped with a debug log."""
    chunks: list = []
    current: list = []
    envelope = len('{"logs":[]}')
    current_size = envelope
    for entry in entries:
        entry_size = len(json.dumps(entry)) + 1  # +1 for inter-entry comma
        if entry_size + envelope > _MAX_BATCH_BYTES:
            log.debug(f"log entry too large ({entry_size}B), dropped")
            continue
        if current and current_size + entry_size > _MAX_BATCH_BYTES:
            chunks.append(current)
            current = [entry]
            current_size = envelope + entry_size
        else:
            current.append(entry)
            current_size += entry_size
    if current:
        chunks.append(current)
    return chunks


class UploadingLogHandler(logging.Handler):
    def __init__(self, uploader: BatchedLogUploader, context: str = "socket-python-cli"):
        super().__init__()
        self._uploader = uploader
        self._context = context

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(_FLUSH_GUARD, "active", False):
            return
        try:
            self._uploader.add({
                "timestamp": _now_str(),
                "level": _LEVEL_MAP.get(record.levelno, "INFO"),
                "message": self.format(record),
                "context": self._context,
            })
        except Exception:
            self.handleError(record)
