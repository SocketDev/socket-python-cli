import pytest
import requests

from socketsecurity import __version__
from socketsecurity.config import CliConfig
from socketsecurity.core.cli_client import CliClient
from socketsecurity.core.socket_config import SocketConfig
from socketsecurity.socketcli import build_socket_sdk


@pytest.mark.parametrize("transport", ["direct", "sdk"])
def test_cli_api_requests_identify_the_same_product(monkeypatch, transport):
    captured = []

    def send(session, request, **kwargs):
        captured.append(request)
        response = requests.Response()
        response.status_code = 200
        response._content = b"{}"
        return response

    monkeypatch.setattr(requests.sessions.Session, "send", send)
    if transport == "direct":
        CliClient(SocketConfig(api_key="synthetic-test-token")).request(
            "organizations"
        )
    else:
        sdk = build_socket_sdk(
            CliConfig(api_token="synthetic-test-token", repo="test-repo")
        )
        sdk.api.do_request("organizations")

    assert len(captured) == 1
    assert captured[0].headers["User-Agent"] == f"socket-python-cli/{__version__}"
    assert captured[0].headers["Authorization"].startswith("Basic ")
