"""Tests for credential redaction in log output.

Log output can be retained by CI and forwarded elsewhere, so credentials must
not reach it.
"""

import dataclasses
import json
import logging

import pytest

from socketsecurity.config import CliConfig
from socketsecurity.core.classes import Diff
from socketsecurity.output import OutputHandler
from socketsecurity.redaction import REDACTED, is_sensitive_name, redact_mapping, redact_url

TOKEN = "sk-not-a-real-token-abc123"
# Ignore credentials loaded from a developer's environment or .env file.
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
    [
        "api_token",
        "API_TOKEN",
        "github_token",
        "slack_webhook",
        "client_secret",
        "password",
        "auth_header",
        "api_key",
        "authorization",
        "ignore_authorization_token",
    ],
)
def test_credential_field_names_are_recognized(name):
    assert is_sensitive_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "repo",
        "branch",
        "commit_sha",
        "target_path",
        "scm",
        "enable_debug",
        "ignore_authorization",
        "IGNORE_AUTHORIZATION",
    ],
)
def test_ordinary_field_names_are_not_recognized(name):
    assert not is_sensitive_name(name)


def test_webhook_url_keeps_the_host_and_drops_the_secret_path():
    redacted = redact_url(WEBHOOK)
    assert redacted == "https://hooks.slack.com/***redacted***"
    assert "secret" not in redacted


def test_redact_url_strips_userinfo():
    assert redact_url("https://user:hunter2@example.com:8443/path?q=1") == "https://example.com:8443/***redacted***"
    assert "hunter2" not in redact_url("https://user:hunter2@example.com/x")


@pytest.mark.parametrize("value", ["https://[broken/path", "https://example.com:bad-port/secret"])
def test_malformed_urls_are_masked(value):
    assert redact_url(value) == REDACTED
    assert redact_mapping({"webhook_url": value})["webhook_url"] == REDACTED


def test_ipv6_url_keeps_a_valid_host():
    assert redact_url("https://[::1]:8443/secret") == "https://[::1]:8443/***redacted***"


@pytest.mark.parametrize("value", ["Not configured", "", None, "not-a-url"])
def test_non_urls_pass_through_so_placeholders_stay_readable(value):
    assert redact_url(value) == value


def test_redact_mapping_masks_secrets_and_keeps_everything_else():
    out = redact_mapping({"api_token": TOKEN, "slack_webhook": WEBHOOK, "repo": "acme/widgets", "enable_debug": True})
    assert out["api_token"] == REDACTED
    assert out["slack_webhook"] == "https://hooks.slack.com/***redacted***"
    assert out["repo"] == "acme/widgets"
    assert out["enable_debug"] is True


def test_nested_plugin_settings_are_redacted_without_mutating_the_config():
    data = {"plugins": [{"config": {"token": TOKEN, "url": WEBHOOK, "channel": "alerts"}}]}
    redacted = redact_mapping(data)
    plugin = redacted["plugins"][0]["config"]
    assert plugin["token"] == REDACTED
    assert plugin["url"] == "https://hooks.slack.com/***redacted***"
    assert plugin["channel"] == "alerts"
    assert data["plugins"][0]["config"]["token"] == TOKEN


@pytest.mark.parametrize("empty", ["", None])
def test_unset_secrets_are_left_alone(empty):
    """ "No token configured" is useful debugging information, not a secret."""
    assert redact_mapping({"api_token": empty})["api_token"] == empty


def test_config_to_dict_is_still_a_faithful_serializer():
    config = CliConfig.from_args(["--api-token", TOKEN, "--repo", "widgets"])
    assert config.to_dict()["api_token"] == TOKEN


def test_config_to_redacted_dict_masks_the_api_token():
    config = CliConfig.from_args(["--api-token", TOKEN, "--repo", "widgets"])
    assert config.to_redacted_dict()["api_token"] == REDACTED
    assert TOKEN not in str(config.to_redacted_dict())


@pytest.mark.parametrize("policy", ["enforce", "strict", "off"])
def test_ignore_authorization_policy_remains_visible_in_config_debug_output(policy):
    config = CliConfig.from_args(["--api-token", TOKEN, "--repo", "widgets", "--ignore-authorization", policy])
    view = config.to_redacted_dict()
    assert view["ignore_authorization"] == policy
    assert view["api_token"] == REDACTED
    assert redact_mapping({"authorization": f"Bearer {TOKEN}"})["authorization"] == REDACTED


def test_every_credential_field_on_cliconfig_is_redacted():
    """All credential-named config fields must be masked by the logging view."""
    config = CliConfig.from_args(["--api-token", TOKEN, "--repo", "widgets"])
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
    """The configuration debug view must mask credentials."""
    config = CliConfig.from_args(["--api-token", TOKEN, "--repo", "widgets"])
    log = logging.getLogger("socketcli")
    with caplog.at_level(logging.DEBUG, logger="socketcli"):
        log.debug(f"config: {config.to_redacted_dict()}")
    assert TOKEN not in caplog.text
    assert REDACTED in caplog.text


@pytest.mark.parametrize(
    ("urls", "expected_url"),
    [
        (WEBHOOK, f"https://hooks.slack.com/{REDACTED}"),
        ([WEBHOOK, "https://hooks.slack.com/services/another-secret"], REDACTED),
        ([{"url": WEBHOOK, "name": "alerts"}], REDACTED),
        ([], "Not configured"),
        (None, "Not configured"),
        ("", "Not configured"),
    ],
)
def test_slack_debug_output_masks_environment_config_and_webhook(monkeypatch, mocker, caplog, urls, expected_url):
    monkeypatch.setenv("SOCKET_SLACK_CONFIG_JSON", json.dumps({"url": urls, "token": TOKEN}))
    config = CliConfig.from_args(["--api-token", TOKEN, "--repo", "widgets", "--enable-debug"])
    handler = OutputHandler(config, sdk=mocker.Mock())
    mocker.patch.object(handler, "output_console_comments")
    with caplog.at_level(logging.DEBUG, logger="socketcli"):
        handler.handle_output(Diff(id="scan", diff_url="https://socket.dev/report"))
    assert TOKEN not in caplog.text
    assert "XXXXXXXXsecretXXXXXXXX" not in caplog.text
    assert "another-secret" not in caplog.text
    assert "SOCKET_SLACK_CONFIG_JSON environment variable: Set" in caplog.text
    assert f"Slack Webhook URL: {expected_url}" in caplog.text
    assert config.slack_plugin.config["url"] == urls
