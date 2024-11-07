import pytest

# Test data
TEST_API_TOKEN = "test-token"
TEST_API_KEY_ENCODED = "dGVzdC10b2tlbjo="
DEFAULT_API_URL = "https://api.socket.dev/v0"
DEFAULT_TIMEOUT = 30

@pytest.fixture(autouse=True)
def reset_globals():
    """Reset global state after each test"""
    from socketsecurity.core import Core
    yield
    Core.set_api_url(DEFAULT_API_URL)
    Core.set_timeout(DEFAULT_TIMEOUT)

@pytest.fixture
def mock_org_response():
    return {
        "organizations": {
            "test-org-123": {
                "slug": "test-org"
            }
        }
    }
