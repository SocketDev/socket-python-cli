import pytest
from unittest.mock import Mock, patch
import requests
from socketsecurity.core.cli_client import CliClient
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.core.exceptions import APIFailure

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
        assert kwargs['verify'] == True  # Default is True

        # Test with SSL verification disabled
        client.config.allow_unverified_ssl = True
        client.request("test/path")

        args, kwargs = mock_request.call_args
        assert kwargs['verify'] == False

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