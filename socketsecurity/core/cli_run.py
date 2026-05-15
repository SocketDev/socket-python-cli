"""Lifecycle helpers for a CLI run on the Socket backend.

A "run" represents a single CLI invocation. `register_cli_run` opens it and
returns a server-issued `run_id`; `finalize_cli_run` closes it on exit. The
run_id keys the rows that `BatchedLogUploader` POSTs to
`/python-cli-runs/<run_id>/logs` during the run so the dashboard can show
what the user saw in their terminal.

Both calls are best-effort: failures fall back to no-streaming and never
prevent the scan from running.
"""

import json
import logging
from typing import Optional

from .cli_client import CliClient
from .exceptions import APIFailure

log = logging.getLogger("socketcli")


def register_cli_run(
    client: CliClient,
    client_version: str,
) -> Optional[str]:
    try:
        resp = client.request(
            path="python-cli-runs",
            method="POST",
            payload=json.dumps({"client_version": client_version}),
        )
    except APIFailure as e:
        log.debug(f"cli-run register failed (streaming disabled): {e}")
        return None

    try:
        body = resp.json()
    except (ValueError, json.JSONDecodeError) as e:
        log.debug(f"cli-run register: bad JSON body: {e}")
        return None

    run_id = body.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        log.debug(f"cli-run register: missing run_id in response: {body!r}")
        return None
    return run_id


def finalize_cli_run(
    client: CliClient,
    run_id: str,
    status: str = "success",
) -> None:
    try:
        client.request(
            path=f"python-cli-runs/{run_id}/finalize",
            method="POST",
            payload=json.dumps({"status": status}),
        )
    except Exception as e:
        log.debug(f"cli-run finalize failed (swallowed): {e}")
