"""Wire the server log streaming pipeline for one CLI run.

`setup_streaming` registers the run with the backend, attaches handlers that
route the CLI's own log output through both the local terminal and a batched
uploader, and forces the loggers into DEBUG so the upload captures everything
regardless of local terminal verbosity.

Returns a teardown callable to invoke on exit (typically via `atexit.register`).
Returns None if registration failed; in that case nothing was wired up.
"""

import logging
from typing import Callable, Optional

from .cli_client import CliClient
from .cli_run import finalize_cli_run, register_cli_run
from .log_uploader import BatchedLogUploader, UploadingLogHandler

_run_status: str = "success"


def set_run_status(status: str) -> None:
    global _run_status
    _run_status = status


def setup_streaming(
    *,
    client: CliClient,
    cli_logger: logging.Logger,
    sdk_logger: logging.Logger,
    client_version: str,
    integration: Optional[str],
    enable_debug: bool,
) -> Optional[Callable[[], None]]:
    run_id = register_cli_run(
        client,
        client_version=client_version,
        integration=integration,
    )
    if not run_id:
        cli_logger.debug("server log streaming disabled (register failed)")
        return None

    log_uploader = BatchedLogUploader(client, run_id)
    log_uploader.start()
    upload_handler = UploadingLogHandler(log_uploader, context="socket-python-cli")
    upload_handler.setFormatter(logging.Formatter("%(message)s"))

    terminal_handler = logging.StreamHandler()
    terminal_handler.setLevel(logging.DEBUG if enable_debug else logging.INFO)
    terminal_handler.setFormatter(logging.Formatter("%(asctime)s: %(message)s"))

    saved_levels = (cli_logger.level, sdk_logger.level)
    saved_propagate = (cli_logger.propagate, sdk_logger.propagate)
    cli_logger.setLevel(logging.DEBUG)
    sdk_logger.setLevel(logging.DEBUG)
    cli_logger.propagate = False
    sdk_logger.propagate = False
    cli_logger.addHandler(terminal_handler)
    sdk_logger.addHandler(terminal_handler)
    cli_logger.addHandler(upload_handler)
    sdk_logger.addHandler(upload_handler)

    cli_logger.debug(f"server log streaming enabled (run_id={run_id})")

    def teardown() -> None:
        cli_logger.removeHandler(upload_handler)
        sdk_logger.removeHandler(upload_handler)
        log_uploader.stop()
        finalize_cli_run(client, run_id, status=_run_status)
        cli_logger.removeHandler(terminal_handler)
        sdk_logger.removeHandler(terminal_handler)
        cli_logger.setLevel(saved_levels[0])
        sdk_logger.setLevel(saved_levels[1])
        cli_logger.propagate = saved_propagate[0]
        sdk_logger.propagate = saved_propagate[1]

    return teardown
