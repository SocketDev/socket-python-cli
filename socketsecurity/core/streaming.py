"""Server log streaming pipeline for one CLI run.

`StreamingLogs` is a context manager. On enter it registers a run with the
backend, attaches handlers that route the CLI's own log output through both
the local terminal and a batched uploader, and forces the loggers into DEBUG
so the upload captures everything regardless of local terminal verbosity.
On exit it tears the handlers back down and finalizes the run; the status
sent to finalize is inferred from the exception that closed the `with`
block (success / failure / cancelled).

If registration fails the manager becomes a no-op — nothing is wired up and
__exit__ does nothing.
"""

import logging
from typing import Optional

from .cli_client import CliClient
from .cli_run import finalize_cli_run, register_cli_run
from .log_uploader import BatchedLogUploader, UploadingLogHandler


class StreamingLogs:
    def __init__(
        self,
        *,
        client: CliClient,
        cli_logger: logging.Logger,
        sdk_logger: logging.Logger,
        client_version: str,
        upload_logs: Optional[bool],
        enable_debug: bool,
    ):
        self._client = client
        self._loggers = (cli_logger, sdk_logger)
        self._client_version = client_version
        self._upload_logs = upload_logs
        self._enable_debug = enable_debug

        self._run_id: Optional[str] = None
        self._report_run_id: Optional[str] = None
        self._uploader: Optional[BatchedLogUploader] = None
        self._upload_handler: Optional[UploadingLogHandler] = None
        self._terminal_handler: Optional[logging.StreamHandler] = None
        self._saved_levels: tuple = ()
        self._saved_propagate: tuple = ()

    def set_report_run_id(self, report_run_id: Optional[str]) -> None:
        self._report_run_id = report_run_id

    def __enter__(self) -> "StreamingLogs":
        self._run_id = register_cli_run(
            self._client,
            client_version=self._client_version,
            upload_logs=self._upload_logs,
        )
        cli_logger = self._loggers[0]
        if not self._run_id:
            cli_logger.debug("server log streaming not active for this run")
            return self

        self._uploader = BatchedLogUploader(self._client, self._run_id)
        self._uploader.start()
        self._upload_handler = UploadingLogHandler(self._uploader, context="socket-python-cli")
        self._upload_handler.setFormatter(logging.Formatter("%(message)s"))

        self._terminal_handler = logging.StreamHandler()
        self._terminal_handler.setLevel(logging.DEBUG if self._enable_debug else logging.INFO)
        self._terminal_handler.setFormatter(logging.Formatter("%(asctime)s: %(message)s"))

        self._saved_levels = tuple(lg.level for lg in self._loggers)
        self._saved_propagate = tuple(lg.propagate for lg in self._loggers)
        for lg in self._loggers:
            lg.setLevel(logging.DEBUG)
            lg.propagate = False
            lg.addHandler(self._terminal_handler)
            lg.addHandler(self._upload_handler)

        cli_logger.debug(f"server log streaming enabled (run_id={self._run_id})")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if self._run_id is None:
            return False

        status = self._status_for_exit(exc_type, exc_val)
        for lg in self._loggers:
            lg.removeHandler(self._upload_handler)
        self._uploader.stop()
        finalize_cli_run(
            self._client,
            self._run_id,
            status=status,
            report_run_id=self._report_run_id,
        )
        for lg in self._loggers:
            lg.removeHandler(self._terminal_handler)
        for lg, level, propagate in zip(self._loggers, self._saved_levels, self._saved_propagate):
            lg.setLevel(level)
            lg.propagate = propagate
        return False

    @staticmethod
    def _status_for_exit(exc_type, exc_val) -> str:
        if exc_type is None:
            return "success"
        if issubclass(exc_type, KeyboardInterrupt):
            return "cancelled"
        # SystemExit with code 0 / None is a clean exit; non-zero codes signal failure.
        if issubclass(exc_type, SystemExit) and not getattr(exc_val, "code", None):
            return "success"
        return "failure"
