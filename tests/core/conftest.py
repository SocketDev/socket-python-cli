# tests/conftest.py
import json
from pathlib import Path

import pytest
from socketdev.fullscans import (
    CreateFullScanResponse,
    FullScanStreamResponse,
    GetFullScanMetadataResponse,
    StreamDiffResponse,
)
from socketdev.repos import GetRepoResponse
from socketdev.settings import OrgSecurityPolicyResponse


@pytest.fixture
def data_dir():
    return Path(__file__).parent.parent / "data"


@pytest.fixture
def load_json():
    def _load_json(path: Path):
        with open(path) as f:
            return json.load(f)

    return _load_json


# API Response Fixtures
@pytest.fixture
def repo_info_response(data_dir, load_json):
    json_data = load_json(data_dir / "repos" / "repo_info_success.json")
    return GetRepoResponse.from_dict({
        "success": json_data["success"],
        "status": json_data["status"],
        "data": json_data["data"]
    })


@pytest.fixture
def head_scan_metadata(data_dir, load_json):
    json_data = load_json(data_dir / "fullscans" / "head_scan" / "metadata.json")
    return GetFullScanMetadataResponse.from_dict({
        "success": json_data["success"],
        "status": json_data["status"],
        "data": json_data["data"]
    })


@pytest.fixture
def head_scan_stream(data_dir, load_json):
    json_data = load_json(data_dir / "fullscans" / "head_scan" / "stream_scan.json")
    return FullScanStreamResponse.from_dict({
        "success": json_data["success"],
        "status": json_data["status"],
        "artifacts": json_data["artifacts"]
    })


@pytest.fixture
def new_scan_metadata(data_dir, load_json):
    json_data = load_json(data_dir / "fullscans" / "new_scan" / "metadata.json")
    return GetFullScanMetadataResponse.from_dict({
        "success": json_data["success"],
        "status": json_data["status"],
        "data": json_data["data"]
    })


@pytest.fixture
def new_scan_stream(data_dir, load_json):
    json_data = load_json(data_dir / "fullscans" / "new_scan" / "stream_scan.json")
    return FullScanStreamResponse.from_dict({
        "success": json_data["success"],
        "status": json_data["status"],
        "artifacts": json_data["artifacts"]
    })


@pytest.fixture
def stream_diff_response(data_dir, load_json):
    json_data = load_json(data_dir / "fullscans" / "diff" / "stream_diff.json")
    return StreamDiffResponse.from_dict({
        "success": json_data["success"],
        "status": json_data["status"],
        "data": json_data["data"]
    })


@pytest.fixture
def security_policy(data_dir, load_json):
    json_data = load_json(data_dir / "settings" / "security-policy.json")
    return OrgSecurityPolicyResponse.from_dict({
        "success": json_data["success"],
        "status": json_data["status"],
        "securityPolicyRules": json_data["securityPolicyRules"]
    })


@pytest.fixture
def repo_info_error(data_dir, load_json):
    json_data = load_json(data_dir / "repos" / "repo_info_error.json")
    return GetRepoResponse.from_dict({
        "success": json_data["success"],
        "status": json_data["status"],
        "message": json_data["message"],
    })


@pytest.fixture
def repo_info_no_head(data_dir, load_json):
    json_data = load_json(data_dir / "repos" / "repo_info_no_head.json")
    return GetRepoResponse.from_dict({
        "success": json_data["success"],
        "status": json_data["status"],
        "data": json_data["data"]
    })


@pytest.fixture
def create_full_scan_response(data_dir, load_json):
    json_data = load_json(data_dir / "fullscans" / "create_response.json")
    return CreateFullScanResponse.from_dict({
        "success": True,
        "status": 201,
        "data": json_data
    })


# Mock SDK Fixtures
@pytest.fixture
def mock_socket_sdk(mocker):
    """Creates a mock of the socketdev SDK"""
    return mocker.patch("socketdev.socketdev")


@pytest.fixture
def mock_sdk_with_responses(
    mock_socket_sdk,
    repo_info_response,
    repo_info_error,
    repo_info_no_head,
    head_scan_metadata,
    head_scan_stream,
    new_scan_metadata,
    new_scan_stream,
    stream_diff_response,
    security_policy,
    create_full_scan_response,
):
    sdk = mock_socket_sdk.return_value

    # Simple returns
    sdk.settings.get.return_value = security_policy
    sdk.fullscans.post.return_value = create_full_scan_response

    # Argument-based returns
    sdk.repos.repo.side_effect = lambda org_slug, repo_slug: {
        "test": repo_info_response,
        "error": repo_info_error,
        "no-head": repo_info_no_head,
    }[repo_slug]

    sdk.fullscans.metadata.side_effect = lambda org_slug, scan_id: {
        "head": head_scan_metadata,
        "new": new_scan_metadata,
    }[scan_id]

    sdk.fullscans.stream.side_effect = lambda org_slug, scan_id: {
        "head": head_scan_stream,
        "new": new_scan_stream,
    }[scan_id]

    sdk.fullscans.stream_diff.side_effect = (
        lambda org_slug, head_id, new_id: stream_diff_response
    )

    return sdk
