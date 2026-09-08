"""Tests for credential redaction in log output.

The CLI runs in customer CI. Its stdout lands in job logs that are retained,
shared in support tickets and public for public repositories, and the log
streamer uploads records to Socket with no level filter. Credentials must not
reach any of that.
"""

import dataclasses
import logging

import pytest

from socketsecurity.config import CliConfig
from socketsecurity.redaction import REDACTED, is_sensitive_name, redact_mapping, redact_url

TOKEN = "sk-not-a-real-token-abc123"
# CliConfig.from_args reads these before falling back to --api-token, and
# socketcli calls load_dotenv() on import, so a developer's .env leaks in as
# soon as another test module imports it. Clear them so these tests are
# hermetic regardless of collection order.
_TOKEN_ENV_VARS = (
    "SOCKET_SECURITY_API_KEY",
    "SOCKET_SECURITY_API_TOKEN",
    "SOCKET_API_KEY",
    "SOCKET_API_TOKEN",
)


@pytest.fixture(autouse=True)
def _clear_token_env(monkeypatch):
    for name in _TOKEN_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


WEBHOOK = "https://hooks.slack.com/services/T00000/B00000/XXXXXXXXsecretXXXXXXXX"


@pytest.mark.parametrize(
    "name",
    ["api_token", "API_TOKEN", "github_token", "slack_webhook", "client_secret", "password", "auth_header", "api_key"],
)
def test_credential_field_names_are_recognised(name):
    assert is_sensitive_name(name)


@pytest.mark.parametrize("name", ["repo", "branch", "commit_sha", "target_path", "scm", "enable_debug"])
def test_ordinary_field_names_are_not_recognised(name):
    assert not is_sensitive_name(name)


def test_webhook_url_keeps_the_host_and_drops_the_secret_path():
    redacted = redact_url(WEBHOOK)
    assert redacted == "https://hooks.slack.com/***redacted***"
    assert "secret" not in redacted


def test_redact_url_strips_userinfo():
    assert redact_url("https://user:hunter2@example.com:8443/path?q=1") == "https://example.com:8443/***redacted***"
    assert "hunter2" not in redact_url("https://user:hunter2@example.com/x")


@pytest.mark.parametrize("value", ["Not configured", "", None, "not-a-url"])
def test_non_urls_pass_through_so_placeholders_stay_readable(value):
    assert redact_url(value) == value


def test_redact_mapping_masks_secrets_and_keeps_everything_else():
    out = redact_mapping({"api_token": TOKEN, "slack_webhook": WEBHOOK, "repo": "acme/widgets", "enable_debug": True})
    assert out["api_token"] == REDACTED
    assert out["slack_webhook"] == "https://hooks.slack.com/***redacted***"
    assert out["repo"] == "acme/widgets"
    assert out["enable_debug"] is True


@pytest.mark.parametrize("empty", ["", None])
def test_unset_secrets_are_left_alone(empty):
    """ "No token configured" is useful debugging information, not a secret."""
    assert redact_mapping({"api_token": empty})["api_token"] == empty


def test_config_to_dict_is_still_a_faithful_serialiser():
    config = CliConfig.from_args(["--api-token", TOKEN, "--repo", "acme/widgets"])
    assert config.to_dict()["api_token"] == TOKEN


def test_config_to_redacted_dict_masks_the_api_token():
    config = CliConfig.from_args(["--api-token", TOKEN, "--repo", "acme/widgets"])
    assert config.to_redacted_dict()["api_token"] == REDACTED
    assert TOKEN not in str(config.to_redacted_dict())


def test_every_credential_field_on_cliconfig_is_redacted():
    """Guard against a future secret field being added and quietly logged.

    Sets every credential-named field to a sentinel and asserts none of them
    survive into the redacted view, so `github_token` or similar is covered
    without anyone editing this test.
    """
    config = CliConfig.from_args(["--api-token", TOKEN, "--repo", "acme/widgets"])
    sentinels = {}
    for field in dataclasses.fields(CliConfig):
        if is_sensitive_name(field.name):
            sentinel = f"SENTINEL-{field.name}-value"
            setattr(config, field.name, sentinel)
            sentinels[field.name] = sentinel

    assert sentinels, "expected CliConfig to declare at least one credential field"
    rendered = str(config.to_redacted_dict())
    for name, sentinel in sentinels.items():
        assert sentinel not in rendered, f"{name} leaked into the redacted config"


def test_the_config_debug_line_does_not_emit_the_token(caplog):
    """End-to-end guard on the line CodeQL's sibling alert pointed at."""
    config = CliConfig.from_args(["--api-token", TOKEN, "--repo", "acme/widgets"])
    log = logging.getLogger("socketcli")
    with caplog.at_level(logging.DEBUG, logger="socketcli"):
        log.debug(f"config: {config.to_redacted_dict()}")
    assert TOKEN not in caplog.text
    assert REDACTED in caplog.text
