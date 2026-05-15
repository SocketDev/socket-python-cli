import json
from unittest.mock import Mock

from socketsecurity.core.cli_client import CliClient
from socketsecurity.core.cli_run import finalize_cli_run, register_cli_run
from socketsecurity.core.exceptions import APIFailure


def _resp(payload):
    r = Mock()
    r.json.return_value = payload
    return r


def test_register_cli_run_returns_run_id():
    client = Mock(spec=CliClient)
    client.request.return_value = _resp({"run_id": "srv-issued-123"})

    run_id = register_cli_run(client, client_version="1.2.3")

    assert run_id == "srv-issued-123"
    args, kwargs = client.request.call_args
    assert kwargs["path"] == "python-cli-runs"
    assert kwargs["method"] == "POST"
    body = json.loads(kwargs["payload"])
    assert body == {"client_version": "1.2.3"}


def test_register_cli_run_returns_none_on_api_failure():
    client = Mock(spec=CliClient)
    client.request.side_effect = APIFailure("network down")

    assert register_cli_run(client, client_version="1.0.0") is None


def test_register_cli_run_returns_none_on_missing_run_id():
    client = Mock(spec=CliClient)
    client.request.return_value = _resp({})

    assert register_cli_run(client, client_version="1.0.0") is None


def test_register_cli_run_returns_none_on_bad_json():
    bad = Mock()
    bad.json.side_effect = ValueError("not json")
    client = Mock(spec=CliClient)
    client.request.return_value = bad

    assert register_cli_run(client, client_version="1.0.0") is None


def test_finalize_cli_run_posts_status():
    client = Mock(spec=CliClient)
    finalize_cli_run(client, "run-x", status="failure")

    args, kwargs = client.request.call_args
    assert kwargs["path"] == "python-cli-runs/run-x/finalize"
    assert kwargs["method"] == "POST"
    assert json.loads(kwargs["payload"]) == {"status": "failure"}


def test_finalize_cli_run_swallows_errors():
    client = Mock(spec=CliClient)
    client.request.side_effect = APIFailure("network down")

    finalize_cli_run(client, "run-x")  # must not raise
