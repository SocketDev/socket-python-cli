from unittest.mock import Mock, patch
from socketsecurity.core import Core, timeout, api_url
from socketsecurity.core.classes import Package, Purl
from tests.unit import TEST_API_TOKEN, mock_org_response
import sys

# Basic initialization and utility tests
@patch('socketsecurity.core.do_request')
def test_core_initialization(mock_do_request):
    # Mock responses for both API calls
    mock_responses = [
        # First call for get_org_id_slug
        Mock(json=lambda: {"organizations": {"test-org-123": {"slug": "test-org"}}}),
        # Second call for get_security_policy
        Mock(json=lambda: {
            "defaults": {
                "issueRules": {
                    "noTests": {"action": "warn"},
                    "noV1": {"action": "error"}
                }
            },
            "entries": []
        })
    ]
    mock_do_request.side_effect = mock_responses

    core = Core(token=TEST_API_TOKEN)
    assert core.token == f"{TEST_API_TOKEN}:"
    assert core.base_api_url is None
    assert core.request_timeout is None

    # Verify both API calls were made
    assert mock_do_request.call_count == 2

def test_core_set_timeout():
    current_module = sys.modules[__name__]
    core_module = sys.modules['socketsecurity.core']

    print(f"Test module id: {id(current_module)}")
    print(f"Core module id: {id(core_module)}")
    print(f"Timeout in test: {id(timeout)}")
    print(f"Timeout in core: {id(core_module.timeout)}")

    Core.set_timeout(60)
    assert timeout == 60

def test_core_set_api_url():
    test_url = "https://test.api.com"
    Core.set_api_url(test_url)
    assert api_url == test_url

# File handling tests
def test_save_file(tmp_path):
    test_file = tmp_path / "test.txt"
    Core.save_file(str(test_file), "test content")
    assert test_file.read_text() == "test content"

# Package handling tests
def test_create_sbom_dict():
    test_sbom = [{
        "id": "test-pkg@1.0.0",
        "name": "test-pkg",
        "version": "1.0.0",
        "type": "npm",
        "direct": True,
        "topLevelAncestors": [],
        "manifestFiles": [{"file": "package.json"}],
        "alerts": []
    }]

    result = Core.create_sbom_dict(test_sbom)
    assert "test-pkg@1.0.0" in result
    assert result["test-pkg@1.0.0"].name == "test-pkg"

# Capability checking tests
def test_check_alert_capabilities():
    package = Package(**{
        "id": "test-pkg@1.0.0",
        "alerts": [{"type": "envVars"}]
    })

    capabilities = {}
    result = Core.check_alert_capabilities(package, capabilities, package.id)
    assert result[package.id] == ["Environment"]

# PURL creation tests
def test_create_purl():
    packages = {
        "test-pkg@1.0.0": Package(**{
            "id": "test-pkg@1.0.0",
            "name": "test-pkg",
            "version": "1.0.0",
            "type": "npm",
            "direct": True,
            "topLevelAncestors": [],
            "manifestFiles": [{"file": "package.json"}],
            "alerts": []
        })
    }

    purl, package = Core.create_purl("test-pkg@1.0.0", packages)
    assert isinstance(purl, Purl)
    assert purl.name == "test-pkg"
    assert purl.version == "1.0.0"

# API interaction tests
@patch('socketsecurity.core.do_request')
def test_get_org_id_slug(mock_do_request):
    mock_response = Mock()
    mock_response.json.return_value = mock_org_response
    mock_do_request.return_value = mock_response

    org_id, org_slug = Core.get_org_id_slug()
    assert org_id == "test-org-123"
    assert org_slug == "test-org"
