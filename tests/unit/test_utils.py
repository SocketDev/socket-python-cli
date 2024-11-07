import pytest
from unittest.mock import patch
from socketsecurity.core.utils import encode_key, do_request
from socketsecurity.core.exceptions import APIKeyMissing

def test_encode_key():
    """Test API key encoding"""
    token = "test-token:"
    encoded = encode_key(token)
    assert encoded == "dGVzdC10b2tlbjo="

@patch('requests.request')
def test_do_request(mock_request):
    """Test API request utility"""
    do_request(
        path="test/path",
        api_key="encoded-key",
        timeout=30
    )

    mock_request.assert_called_once()
    args = mock_request.call_args
    assert args[1]['timeout'] == 30
    assert args[1]['headers']['Authorization'] == "Basic encoded-key"

def test_do_request_missing_key():
    """Test API request fails without key"""
    with pytest.raises(APIKeyMissing):
        do_request(path="test/path")