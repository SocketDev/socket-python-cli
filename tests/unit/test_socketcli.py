import sys

import pytest
from socketdev.exceptions import APIFailure

from socketsecurity import socketcli
from socketsecurity.core.exceptions import RequestTimeoutExceeded


# ---------------------------------------------------------------------------
# Exit code semantics (spec v2.3.0): infrastructure errors map to
# config.exit_code_on_api_error (default 3), INDEPENDENT of --disable-blocking.
# ---------------------------------------------------------------------------


def test_api_failure_exits_with_default_exit_code_on_api_error(monkeypatch):
    def fail_main_code():
        raise APIFailure("upstream request timeout")

    monkeypatch.setattr(socketcli, "main_code", fail_main_code)
    monkeypatch.setattr(sys, "argv", ["socketcli", "--api-token", "test"])

    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()

    assert exc_info.value.code == 3


def test_api_failure_exits_3_even_with_disable_blocking(monkeypatch):
    # Breaking change for 2.3.0: --disable-blocking no longer zeroes out
    # infrastructure errors. Use --exit-code-on-api-error 0 for that.
    def fail_main_code():
        raise APIFailure("upstream request timeout")

    monkeypatch.setattr(socketcli, "main_code", fail_main_code)
    monkeypatch.setattr(
        sys, "argv", ["socketcli", "--api-token", "test", "--disable-blocking"]
    )

    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()

    assert exc_info.value.code == 3


def test_request_timeout_exceeded_exits_with_configured_code(monkeypatch):
    def fail_main_code():
        raise RequestTimeoutExceeded("scan diff timed out after 1200s")

    monkeypatch.setattr(socketcli, "main_code", fail_main_code)
    monkeypatch.setattr(sys, "argv", ["socketcli", "--api-token", "test"])

    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()

    assert exc_info.value.code == 3


def test_exit_code_on_api_error_remaps_timeout(monkeypatch):
    def fail_main_code():
        raise RequestTimeoutExceeded("scan diff timed out after 1200s")

    monkeypatch.setattr(socketcli, "main_code", fail_main_code)
    monkeypatch.setattr(
        sys,
        "argv",
        ["socketcli", "--api-token", "test", "--exit-code-on-api-error", "100"],
    )

    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()

    assert exc_info.value.code == 100


def test_exit_code_on_api_error_zero_swallows_infrastructure_errors(monkeypatch):
    def fail_main_code():
        raise RequestTimeoutExceeded("scan diff timed out after 1200s")

    monkeypatch.setattr(socketcli, "main_code", fail_main_code)
    monkeypatch.setattr(
        sys,
        "argv",
        ["socketcli", "--api-token", "test", "--exit-code-on-api-error", "0"],
    )

    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()

    assert exc_info.value.code == 0


def test_generic_exception_uses_exit_code_on_api_error(monkeypatch):
    def fail_main_code():
        raise RuntimeError("unexpected boom")

    monkeypatch.setattr(socketcli, "main_code", fail_main_code)
    monkeypatch.setattr(
        sys,
        "argv",
        ["socketcli", "--api-token", "test", "--exit-code-on-api-error", "7"],
    )

    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()

    assert exc_info.value.code == 7


# ---------------------------------------------------------------------------
# Buildkite-aware log formatting (spec §3): ^^^ +++ / --- markers only
# emitted when BUILDKITE=true; bare log.error otherwise.
# ---------------------------------------------------------------------------


def test_emit_infrastructure_error_no_buildkite_has_no_markers(
    monkeypatch, capsys, caplog
):
    monkeypatch.setattr(socketcli, "IS_BUILDKITE", False)
    with caplog.at_level("ERROR", logger="socketcli"):
        socketcli._emit_infrastructure_error(
            "something failed", hint="just so you know"
        )
    captured = capsys.readouterr()
    assert "^^^ +++" not in captured.out
    assert "--- :warning:" not in captured.out
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert "soft_fail" not in log_text


def test_emit_infrastructure_error_buildkite_emits_markers(
    monkeypatch, capsys, caplog
):
    monkeypatch.setattr(socketcli, "IS_BUILDKITE", True)
    with caplog.at_level("ERROR", logger="socketcli"):
        socketcli._emit_infrastructure_error(
            "something failed", hint="just so you know"
        )
    captured = capsys.readouterr()
    # Markers go to stdout via print() so pytest's capsys catches them cleanly.
    assert "^^^ +++" in captured.out
    assert "--- :warning: Socket Infrastructure Error" in captured.out
    # The soft_fail tip is appended via log.error() -- caplog captures it.
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert "soft_fail" in log_text


def test_emit_infrastructure_error_omits_traceback_by_default(monkeypatch, capsys):
    monkeypatch.setattr(socketcli, "IS_BUILDKITE", False)
    try:
        raise ValueError("boom")
    except ValueError:
        socketcli._emit_infrastructure_error("wrapped", include_traceback=False)
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out


def test_emit_infrastructure_error_includes_traceback_on_request(monkeypatch, capsys):
    monkeypatch.setattr(socketcli, "IS_BUILDKITE", False)
    try:
        raise ValueError("boom")
    except ValueError:
        socketcli._emit_infrastructure_error("wrapped", include_traceback=True)
    captured = capsys.readouterr()
    # traceback.print_exc() writes to sys.stderr by default.
    assert "Traceback" in captured.err
    assert "ValueError: boom" in captured.err
