import hashlib

import pytest
from socketdev import socketdev

from socketsecurity.config import (
    API_TOKEN_ENVIRONMENT_VARIABLES,
    CliConfig,
    select_api_token,
)
from socketsecurity.core.cli_client import CliClient
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.core.tools.reachability import ReachabilityAnalyzer
from socketsecurity.retired_api_token import (
    RETIRED_API_TOKEN_ERROR,
    _matches_retired_digest,
    _reject_retired_api_token,
)


def test_retired_api_token_rejection_redacts_token_and_digest():
    token = "synthetic-retired-token"
    digest = hashlib.sha256(token.encode()).hexdigest()

    with pytest.raises(ValueError) as exc_info:
        _reject_retired_api_token(token, digest)

    assert str(exc_info.value) == RETIRED_API_TOKEN_ERROR
    assert token not in str(exc_info.value)
    assert digest not in str(exc_info.value)
    assert _matches_retired_digest(f" {token} ", digest)


def test_cli_config_preserves_token_environment_precedence(monkeypatch):
    for name in API_TOKEN_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(API_TOKEN_ENVIRONMENT_VARIABLES[0], "first-env-token")
    monkeypatch.setenv(API_TOKEN_ENVIRONMENT_VARIABLES[1], "second-env-token")

    config = CliConfig.from_args(["--api-token", "argument-token"])

    assert config.api_token == "first-env-token"


def test_cli_config_uses_argument_when_token_environment_is_empty(monkeypatch):
    for name in API_TOKEN_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(name, raising=False)

    config = CliConfig.from_args(["--api-token", "argument-token"])

    assert config.api_token == "argument-token"


def test_cli_http_and_reachability_construction_accept_safe_token_without_network():
    token = "synthetic-safe-token"
    config = SocketConfig(api_key=token)
    client = CliClient(config)
    sdk = socketdev(token=token)
    analyzer = ReachabilityAnalyzer(sdk, token)

    assert client.config.api_key == token
    assert analyzer.api_token == token


@pytest.mark.parametrize("token", [None, "different-token"])
def test_nonretired_api_token_is_accepted(token):
    digest = hashlib.sha256(b"synthetic-retired-token").hexdigest()
    _reject_retired_api_token(token, digest)


@pytest.mark.parametrize("name", API_TOKEN_ENVIRONMENT_VARIABLES)
def test_each_cli_environment_source_is_supported(name):
    assert select_api_token({name: "selected-token"}, "argument-token") == "selected-token"
