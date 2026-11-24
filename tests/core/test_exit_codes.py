"""Exit codes are decided in one place, so the exit flags apply to every run.

Failures that are not security findings raise InfrastructureError and reach
``socketcli.cli()``, which applies ``--disable-blocking`` and
``--exit-code-on-api-error``. Invalid flags exit 2 like argparse's own usage
errors, and Ctrl+C exits 130. See socketsecurity.exit_codes.
"""
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests
from socketdev.diffscans import DiffScans
from socketdev.exceptions import (
    APIFailure,
    APIInsufficientPermissions,
    APIResourceNotFound,
)

from socketsecurity import socketcli
from socketsecurity.config import CliConfig
from socketsecurity.core import Core
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.exit_codes import IncompleteComparisonError, InfrastructureError


def _run_cli(monkeypatch, argv, error):
    def fail_main_code(config=None):
        raise error

    monkeypatch.setattr(socketcli, "main_code", fail_main_code)
    monkeypatch.setattr(sys, "argv", ["socketcli", "--api-token", "test", *argv])
    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()
    return exc_info.value.code


@pytest.mark.parametrize(
    "argv, expected",
    [
        ([], 3),
        (["--exit-code-on-api-error", "100"], 100),
        (["--disable-blocking"], 0),
        (["--disable-blocking", "--exit-code-on-api-error", "100"], 0),
    ],
)
def test_infrastructure_error_honors_exit_flags(monkeypatch, capsys, argv, expected):
    code = _run_cli(monkeypatch, argv, InfrastructureError("token missing a scope"))

    assert code == expected
    # Expected failures are reported without a traceback.
    assert "Traceback" not in capsys.readouterr().err


def test_infrastructure_error_message_is_logged(monkeypatch, caplog):
    _run_cli(monkeypatch, [], InfrastructureError("Unable to get GitLab API Token"))

    assert "Unable to get GitLab API Token" in caplog.text


def test_keyboard_interrupt_with_disable_blocking_exits_0(monkeypatch):
    assert _run_cli(monkeypatch, ["--disable-blocking"], KeyboardInterrupt()) == 0


def test_invalid_flags_exit_2_even_with_disable_blocking():
    """A misconfigured run never scanned anything, so --disable-blocking doesn't apply."""
    with pytest.raises(SystemExit) as exc_info:
        CliConfig.from_args([
            "--api-token", "test", "--disable-blocking",
            "--base-scan-id", "a", "--base-commit-sha", "b",
        ])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("argv, expected", [([], 3), (["--disable-blocking"], 0)])
def test_missing_api_token_honors_exit_flags(monkeypatch, caplog, argv, expected):
    """A fork pull request has no secrets; --disable-blocking should keep it green."""
    monkeypatch.delenv("SOCKET_SECURITY_API_TOKEN", raising=False)
    monkeypatch.delenv("SOCKET_SECURITY_API_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", ["socketcli", *argv])

    with pytest.raises(SystemExit) as exc_info:
        socketcli.cli()

    assert exc_info.value.code == expected
    assert "Socket API Token not found" in caplog.text


# --- Repository lookup ---------------------------------------------------------------


@pytest.fixture
def core():
    sdk = MagicMock()
    return Core(config=SocketConfig(api_key="test_key"), sdk=sdk)


def test_repo_lookup_permission_error_does_not_try_to_create(core):
    """A token without repo:list is reported as such, not as a missing repository."""
    core.sdk.repos.repo.side_effect = APIInsufficientPermissions(status_code=403)

    with pytest.raises(InfrastructureError, match="repo:list"):
        core.get_repo_info("my-repo")

    core.sdk.repos.post.assert_not_called()


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
@pytest.mark.parametrize("response_kind", ["exception", "response"])
def test_repo_lookup_only_creates_for_not_found(core, status, response_kind):
    if response_kind == "exception":
        core.sdk.repos.repo.side_effect = APIFailure("lookup failed", status_code=status)
    else:
        core.sdk.repos.repo.return_value = MagicMock(success=False, status=status, message="lookup failed")

    with pytest.raises(InfrastructureError, match=f"HTTP {status}"):
        core.get_repo_info("my-repo")

    core.sdk.repos.post.assert_not_called()


def test_repo_lookup_not_found_creates_the_repository(core):
    created = MagicMock(data="repo-info")
    core.sdk.repos.repo.side_effect = [APIResourceNotFound(status_code=404), created]
    core.sdk.repos.post.return_value = {"id": "repo"}

    assert core.get_repo_info("my-repo") == "repo-info"
    core.sdk.repos.post.assert_called_once()


def test_repo_creation_failure_raises_infrastructure_error(core):
    core.sdk.repos.repo.side_effect = APIResourceNotFound(status_code=404)
    core.sdk.repos.post.side_effect = APIFailure("forbidden", status_code=403)

    with pytest.raises(InfrastructureError, match="repo:create"):
        core.get_repo_info("my-repo")


# --- Incomplete comparisons ----------------------------------------------------------


EMPTY_ARTIFACTS = {"added": [], "removed": [], "unchanged": [], "replaced": [], "updated": []}


@pytest.fixture(params=[{}, None, "omitted", "top-level"])
def incomplete_response(request):
    if request.param == "top-level":
        return {"incomplete": True}
    scan = {"id": "diff-scan-1", "incomplete": True}
    if request.param != "omitted":
        scan["artifacts"] = request.param
    return {"diff_scan": scan}


def test_incomplete_comparison_raises(core, incomplete_response):
    core.sdk.diffscans.create_from_ids.return_value = {"diff_scan": {"id": "diff-scan-1"}}
    core.sdk.diffscans.get.return_value = incomplete_response

    with pytest.raises(IncompleteComparisonError, match="incomplete"):
        core.get_diff_scan_artifacts("head", "new")


def test_incomplete_comparison_does_not_fall_back_to_streaming(core, incomplete_response):
    """The streaming comparison reads the same scans, so it can't fill the gap."""
    core.sdk.diffscans.create_from_ids.return_value = {"diff_scan": {"id": "diff-scan-1"}}
    core.sdk.diffscans.get.return_value = incomplete_response

    with pytest.raises(IncompleteComparisonError):
        core.get_added_and_removed_packages("head", "new")

    core.sdk.fullscans.stream_diff.assert_not_called()


@pytest.fixture(params=[
    pytest.param({"incomplete": False, "artifacts": None}, id="null-artifacts-complete"),
    pytest.param({"artifacts": None}, id="null-artifacts-flag-unset"),
    pytest.param({}, id="artifacts-absent-flag-unset"),
    pytest.param({"artifacts": []}, id="artifacts-not-an-object"),
    pytest.param({"artifacts": {}}, id="empty-artifacts-object"),
    pytest.param({"artifacts": {**EMPTY_ARTIFACTS, "added": None}}, id="null-added"),
    pytest.param({"artifacts": {**EMPTY_ARTIFACTS, "unchanged": None}}, id="null-unchanged"),
    pytest.param({"artifacts": {**EMPTY_ARTIFACTS, "removed": {}}}, id="removed-not-a-list"),
    pytest.param({"artifacts": {**EMPTY_ARTIFACTS, "updated": "invalid"}}, id="updated-not-a-list"),
    pytest.param({"artifacts": {key: [] for key in EMPTY_ARTIFACTS if key != "replaced"}}, id="missing-replaced"),
])
def invalid_artifacts_response(request):
    return {"diff_scan": {"id": "diff-scan-1", **request.param}}


def test_invalid_artifacts_do_not_fall_back_to_streaming(core, invalid_artifacts_response):
    core.sdk.diffscans.create_from_ids.return_value = {"diff_scan": {"id": "diff-scan-1"}}
    core.sdk.diffscans.get.return_value = invalid_artifacts_response

    with pytest.raises(IncompleteComparisonError, match="missing a valid artifacts"):
        core.get_added_and_removed_packages("head", "new")

    core.sdk.fullscans.stream_diff.assert_not_called()


@pytest.mark.parametrize("argv, expected", [
    ([], 3),
    (["--exit-code-on-api-error", "42"], 42),
    (["--disable-blocking"], 0),
    (["--disable-blocking", "--exit-code-on-api-error", "42"], 0),
])
@pytest.mark.parametrize("strict", [[], ["--strict-blocking"]], ids=["standard", "strict"])
def test_invalid_artifacts_follow_exit_policy(monkeypatch, caplog, argv, expected, strict):
    sdk = MagicMock()
    sdk.org.get.return_value = {"organizations": {"org-id": {"slug": "acme"}}}
    sdk.diffscans.create_from_ids.return_value = {"diff_scan": {"id": "diff-scan-1"}}
    sdk.diffscans.get.return_value = {"diff_scan": {"id": "diff-scan-1", "artifacts": {}}}
    monkeypatch.setattr(socketcli, "build_socket_sdk", lambda config: sdk)
    monkeypatch.setattr(socketcli, "StreamingLogs", lambda **kwargs: nullcontext(MagicMock()))
    monkeypatch.setattr(socketcli, "apply_git_context", lambda config: (False, None))
    monkeypatch.setattr(Core, "has_manifest_files", lambda self, files: True)
    monkeypatch.setattr(Core, "create_full_scan", lambda *args, **kwargs: SimpleNamespace(id="new"))
    report = MagicMock()
    monkeypatch.setattr(socketcli.OutputHandler, "handle_output", report)
    monkeypatch.setattr(sys, "argv", [
        "socketcli", "--api-token", "test", "--scm", "api", "--integration", "api",
        "--repo", "repo", "--branch", "feature", "--enable-diff", "--base-scan-id", "head",
        "--files", '["package.json"]', *strict, *argv,
    ])

    with pytest.raises(SystemExit) as result:
        socketcli.cli()

    assert result.value.code == expected
    assert "missing a valid artifacts.added list" in caplog.text
    sdk.diffscans.get.assert_called_once()
    sdk.fullscans.stream_diff.assert_not_called()
    report.assert_not_called()


class StreamingFallback(Exception):
    """Sentinel for a streaming comparison call."""


@pytest.mark.parametrize("response", [
    pytest.param({}, id="empty-dict"),
    pytest.param({"diff_scan": None}, id="diff-scan-null"),
    pytest.param({"diff_scan": []}, id="diff-scan-not-an-object"),
])
def test_response_without_diff_scan_object_falls_back_to_streaming(core, response):
    core.sdk.diffscans.create_from_ids.return_value = {"diff_scan": {"id": "diff-scan-1"}}
    core.sdk.diffscans.get.return_value = response
    core.sdk.fullscans.stream_diff.side_effect = StreamingFallback

    with pytest.raises(RuntimeError, match="no diff_scan object"):
        core.get_diff_scan_artifacts("head", "new")

    with pytest.raises(StreamingFallback):
        core.get_added_and_removed_packages("head", "new")
    core.sdk.fullscans.stream_diff.assert_called_once()


def test_http_204_through_the_sdk_falls_back_to_streaming(core):
    """The SDK maps HTTP 204 to an empty response."""
    no_content = requests.Response()
    no_content.status_code = 204
    no_content._content = b""
    api = MagicMock()
    api.do_request.return_value = no_content
    core.sdk.diffscans = DiffScans(api)
    core.sdk.diffscans.create_from_ids = MagicMock(return_value={"diff_scan": {"id": "diff-scan-1"}})
    core.sdk.fullscans.stream_diff.side_effect = StreamingFallback

    with pytest.raises(StreamingFallback):
        core.get_added_and_removed_packages("head", "new")


def test_omitted_unchanged_bucket_is_still_a_result(core):
    core.cli_config = CliConfig(api_token="test", repo="repo")
    core.sdk.diffscans.create_from_ids.return_value = {"diff_scan": {"id": "diff-scan-1"}}
    core.sdk.diffscans.get.return_value = {"diff_scan": {
        "id": "diff-scan-1", "incomplete": False,
        "artifacts": {**EMPTY_ARTIFACTS, "unchanged": None},
    }}

    artifacts = core.get_diff_scan_artifacts("head", "new")

    assert core.sdk.diffscans.get.call_args.kwargs["params"]["omit_unchanged"] == "true"
    assert artifacts.unchanged == []


def test_complete_comparison_is_returned(core):
    core.sdk.diffscans.create_from_ids.return_value = {"diff_scan": {"id": "diff-scan-1"}}
    core.sdk.diffscans.get.return_value = {
        "diff_scan": {"id": "diff-scan-1", "incomplete": False, "artifacts": EMPTY_ARTIFACTS},
    }

    artifacts = core.get_diff_scan_artifacts("head", "new")

    assert artifacts.to_dict() == EMPTY_ARTIFACTS
