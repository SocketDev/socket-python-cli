import sys

import pytest
from socketdev.exceptions import APIFailure

from socketsecurity import socketcli


def test_cli_honors_disable_blocking_for_api_failures(monkeypatch):
    def fail_main_code():
        raise APIFailure("upstream request timeout")

    monkeypatch.setattr(socketcli, "main_code", fail_main_code)
    monkeypatch.setattr(
        sys,
        "argv",
        ["socketcli", "--api-token", "test", "--disable-blocking"],
    )

    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()

    assert exc_info.value.code == 0


def test_cli_returns_error_for_api_failures_without_disable_blocking(monkeypatch):
    def fail_main_code():
        raise APIFailure("upstream request timeout")

    monkeypatch.setattr(socketcli, "main_code", fail_main_code)
    monkeypatch.setattr(sys, "argv", ["socketcli", "--api-token", "test"])

    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()

    assert exc_info.value.code == 3
