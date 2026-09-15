from unittest.mock import Mock, patch

import pytest
import requests

from socketsecurity.core.cli_client import CliClient
from socketsecurity.core.exceptions import APIFailure
from socketsecurity.core.socket_config import SocketConfig


@pytest.fixture
def config():
    return SocketConfig(
        api_key="test_key",
        timeout=30,
        allow_unverified_ssl=False
    )

@pytest.fixture
def client(config):
    return CliClient(config)

def test_encode_key():
    """Test the static key encoding method"""
    encoded = CliClient._encode_key("test_key")
    assert encoded == "dGVzdF9rZXk6"  # base64 of "test_key:"

def test_request_builds_correct_url(client):
    """Test URL construction"""
    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client.request("test/path")

        mock_request.assert_called_once()
        args, kwargs = mock_request.call_args
        assert kwargs['url'] == "https://api.socket.dev/v0/test/path"

def test_request_uses_config_timeout(client):
    """Test timeout is passed from config"""
    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client.request("test/path")

        mock_request.assert_called_once()
        args, kwargs = mock_request.call_args
        assert kwargs['timeout'] == 30

def test_request_handles_api_error():
    """Test error handling"""
    config = SocketConfig(api_key="test_key")
    client = CliClient(config)

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.raise_for_status.side_effect = requests.exceptions.RequestException("Test error")
        mock_request.return_value = mock_response

        with pytest.raises(APIFailure):
            client.request("test/path")

def test_request_uses_custom_headers(client):
    """Test that custom headers override defaults"""
    custom_headers = {"Authorization": "Bearer token", "Custom": "Value"}

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client.request("test/path", headers=custom_headers)

        args, kwargs = mock_request.call_args
        assert kwargs['headers'] == custom_headers

def test_request_uses_custom_base_url(client):
    """Test that custom base_url overrides default"""
    custom_base = "https://custom.api.com"

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client.request("test/path", base_url=custom_base)

        args, kwargs = mock_request.call_args
        assert kwargs['url'] == f"{custom_base}/test/path"

def test_request_ssl_verification(client):
    """Test SSL verification setting from config"""
    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client.request("test/path")

        args, kwargs = mock_request.call_args
        assert kwargs['verify']  # Default is True

        # Test with SSL verification disabled
        client.config.allow_unverified_ssl = True
        client.request("test/path")

        args, kwargs = mock_request.call_args
        assert not kwargs['verify']

def test_request_with_payload(client):
    """Test request with payload data"""
    payload = {"key": "value"}

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client.request("test/path", method="POST", payload=payload)

        args, kwargs = mock_request.call_args
        assert kwargs['method'] == "POST"
        assert kwargs['data'] == payload


def test_post_telemetry_events_sends_individually(client):
    """Test that telemetry events are posted one at a time to v0 API"""
    import json

    events = [
        {"event_kind": "user-action", "client_action": "ignore_alerts", "artifact_purl": "pkg:npm/foo@1.0.0"},
        {"event_kind": "user-action", "client_action": "ignore_alerts", "artifact_purl": "pkg:npm/bar@2.0.0"},
    ]

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 201
        mock_request.return_value = mock_response

        client.post_telemetry_events("test-org", events)

        assert mock_request.call_count == 2

        first_call = mock_request.call_args_list[0]
        assert first_call.kwargs['url'] == "https://api.socket.dev/v0/orgs/test-org/telemetry"
        assert first_call.kwargs['method'] == "POST"
        assert first_call.kwargs['data'] == json.dumps(events[0])

        second_call = mock_request.call_args_list[1]
        assert second_call.kwargs['data'] == json.dumps(events[1])


def test_post_telemetry_events_continues_on_failure(client):
    """Test that a failed event does not prevent subsequent events from being sent"""

    events = [
        {"event_kind": "user-action", "artifact_purl": "pkg:npm/foo@1.0.0"},
        {"event_kind": "user-action", "artifact_purl": "pkg:npm/bar@2.0.0"},
    ]

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 201
        mock_request.side_effect = [
            requests.exceptions.ConnectionError("timeout"),
            mock_response,
        ]

        client.post_telemetry_events("test-org", events)

        assert mock_request.call_count == 2


def test_request_preserves_the_http_status_on_failure():
    """The status is the only thing that survives translation to APIFailure.

    Callers that must react to a specific code -- the GitLab auth fallback on a
    401, and APIFailure.is_transient_error -- have no other way to recover it once
    the requests exception is gone.
    """
    config = SocketConfig(api_key="test_key")
    client = CliClient(config)

    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 401
        error = requests.exceptions.HTTPError("401 Client Error")
        error.response = mock_response
        mock_response.raise_for_status.side_effect = error
        mock_request.return_value = mock_response

        with pytest.raises(APIFailure) as exc_info:
            client.request("test/path")

    assert exc_info.value.status_code == 401


def test_request_tolerates_a_failure_with_no_response():
    """A connection error never reached a server, so there is no status to carry."""
    config = SocketConfig(api_key="test_key")
    client = CliClient(config)

    with patch('requests.request') as mock_request:
        mock_request.side_effect = requests.exceptions.ConnectionError("no route")

        with pytest.raises(APIFailure) as exc_info:
            client.request("test/path")

    assert exc_info.value.status_code is None


def test_a_handler_written_against_the_sdk_exception_catches_client_failures():
    """socketsecurity.core imports the SDK's APIFailure in every handler, while
    CliClient raises the CLI's own. They must not be independent types."""
    from socketdev.exceptions import APIFailure as SdkAPIFailure

    config = SocketConfig(api_key="test_key")
    client = CliClient(config)

    with patch('requests.request') as mock_request:
        mock_request.side_effect = requests.exceptions.ConnectionError("no route")

        with pytest.raises(SdkAPIFailure):
            client.request("test/path")
