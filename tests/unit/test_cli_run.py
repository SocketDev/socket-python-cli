import json
from unittest.mock import Mock

from socketsecurity.core.cli_client import CliClient
from socketsecurity.core.cli_run import finalize_cli_run, register_cli_run
from socketsecurity.core.exceptions import APIFailure


def _resp(payload):
    r = Mock()
    r.json.return_value = payload
    return r


def test_register_cli_run_returns_run_id_when_enabled():
    client = Mock(spec=CliClient)
    client.request.return_value = _resp({
        "log_streaming_enabled": True,
        "run_id": "srv-issued-123",
    })

    run_id = register_cli_run(client, client_version="1.2.3", upload_logs=True)

    assert run_id == "srv-issued-123"
    args, kwargs = client.request.call_args
    assert kwargs["path"] == "python-cli-runs"
    assert kwargs["method"] == "POST"
    body = json.loads(kwargs["payload"])
    assert body == {"client_version": "1.2.3", "share_logs": True, "decline_logs": False}


def test_register_cli_run_returns_none_when_disabled_by_server():
    client = Mock(spec=CliClient)
    client.request.return_value = _resp({
        "log_streaming_enabled": False,
        "run_id": None,
    })

    assert register_cli_run(client, client_version="1.0.0", upload_logs=None) is None


def test_register_cli_run_sends_both_false_when_unset():
    client = Mock(spec=CliClient)
    client.request.return_value = _resp({"log_streaming_enabled": False, "run_id": None})

    register_cli_run(client, client_version="1.0.0", upload_logs=None)

    body = json.loads(client.request.call_args.kwargs["payload"])
    assert body == {"client_version": "1.0.0", "share_logs": False, "decline_logs": False}


def test_register_cli_run_sends_decline_logs_true_when_opted_out():
    client = Mock(spec=CliClient)
    client.request.return_value = _resp({"log_streaming_enabled": False, "run_id": None})

    register_cli_run(client, client_version="1.0.0", upload_logs=False)

    body = json.loads(client.request.call_args.kwargs["payload"])
    assert body == {"client_version": "1.0.0", "share_logs": False, "decline_logs": True}


def test_register_cli_run_returns_none_on_api_failure():
    client = Mock(spec=CliClient)
    client.request.side_effect = APIFailure("network down")

    assert register_cli_run(client, client_version="1.0.0", upload_logs=True) is None


def test_register_cli_run_returns_none_on_missing_run_id_when_enabled():
    client = Mock(spec=CliClient)
    client.request.return_value = _resp({"log_streaming_enabled": True})

    assert register_cli_run(client, client_version="1.0.0", upload_logs=True) is None


def test_register_cli_run_returns_none_on_bad_json():
    bad = Mock()
    bad.json.side_effect = ValueError("not json")
    client = Mock(spec=CliClient)
    client.request.return_value = bad

    assert register_cli_run(client, client_version="1.0.0", upload_logs=True) is None


def test_register_cli_run_returns_none_on_non_dict_json_body():
    # Server (mis)behavior: JSON parses but isn't an object. body.get(...) would
    # raise AttributeError; the broad except must catch it so the scan continues.
    client = Mock(spec=CliClient)
    client.request.return_value = _resp([1, 2, 3])

    assert register_cli_run(client, client_version="1.0.0", upload_logs=True) is None


def test_register_cli_run_returns_none_on_unexpected_exception():
    # Defense-in-depth: any unexpected exception from client.request must be
    # swallowed so streaming registration can never break the scan.
    client = Mock(spec=CliClient)
    client.request.side_effect = RuntimeError("boom")

    assert register_cli_run(client, client_version="1.0.0", upload_logs=True) is None


def test_finalize_cli_run_posts_status_and_null_report_run_id_by_default():
    client = Mock(spec=CliClient)
    finalize_cli_run(client, "run-x", status="failure")

    args, kwargs = client.request.call_args
    assert kwargs["path"] == "python-cli-runs/run-x/finalize"
    assert kwargs["method"] == "POST"
    assert json.loads(kwargs["payload"]) == {"status": "failure", "report_run_id": None}


def test_finalize_cli_run_includes_report_run_id_when_provided():
    client = Mock(spec=CliClient)
    finalize_cli_run(client, "run-x", status="success", report_run_id="fs-abc")

    body = json.loads(client.request.call_args.kwargs["payload"])
    assert body == {"status": "success", "report_run_id": "fs-abc"}


def test_finalize_cli_run_swallows_errors():
    client = Mock(spec=CliClient)
    client.request.side_effect = APIFailure("network down")

    finalize_cli_run(client, "run-x")  # must not raise
