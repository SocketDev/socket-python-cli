import pytest
from socketsecurity.core.config import CoreConfig

def test_config_initialization() -> None:
    """Test basic config initialization with defaults"""
    config = CoreConfig(token="test-token")

    assert config.token == "test-token:"
    assert config.api_url == CoreConfig.DEFAULT_API_URL
    assert config.timeout == CoreConfig.DEFAULT_TIMEOUT
    assert config.enable_all_alerts is False
    assert config.allow_unverified_ssl is False

def test_config_custom_values() -> None:
    """Test config with custom values"""
    config = CoreConfig(
        token="test-token",
        api_url="https://custom.api",
        timeout=60,
        enable_all_alerts=True,
        allow_unverified_ssl=True
    )

    assert config.token == "test-token:"
    assert config.api_url == "https://custom.api"
    assert config.timeout == 60
    assert config.enable_all_alerts is True
    assert config.allow_unverified_ssl is True

def test_config_validation() -> None:
    """Test business rule validation"""
    # Test empty token
    with pytest.raises(ValueError, match="Token is required"):
        CoreConfig(token="")

    # Test invalid timeout
    with pytest.raises(ValueError, match="Timeout must be positive"):
        CoreConfig(token="test", timeout=0)

def test_token_formatting() -> None:
    """Test token colon suffix business rule"""
    # Without colon
    config = CoreConfig(token="test-token")
    assert config.token == "test-token:"

    # Already has colon
    config = CoreConfig(token="test-token:")
    assert config.token == "test-token:"
