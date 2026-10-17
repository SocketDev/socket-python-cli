"""Reusable localhost HTTP fixture for real Socket SDK transport tests."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit


@dataclass
class SocketRequest:
    method: str
    path: str
    query: Dict[str, List[str]]
    headers: Dict[str, str]
    body: bytes


@dataclass
class SocketResponse:
    status: int
    payload: object
    raw_body: Optional[bytes] = None


Route = Callable[[SocketRequest], SocketResponse]


class SocketApiFixture:
    def __init__(self) -> None:
        self.requests: List[SocketRequest] = []
        self._routes: Dict[Tuple[str, str], Route] = {}
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("Socket API fixture is not running")
        host, port = self._server.server_address
        return f"http://{host}:{port}/v0"

    def route(
        self,
        method: str,
        path: str,
        response: SocketResponse | Route,
    ) -> None:
        if callable(response):
            handler = response
        else:

            def handler(_request: SocketRequest) -> SocketResponse:
                return response

        self._routes[(method.upper(), path)] = handler

    def start(self) -> None:
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self._dispatch()

            def do_POST(self) -> None:
                self._dispatch()

            def _dispatch(self) -> None:
                parsed = urlsplit(self.path)
                length = int(self.headers.get("Content-Length", "0"))
                request = SocketRequest(
                    method=self.command,
                    path=parsed.path.removeprefix("/v0/"),
                    query=parse_qs(parsed.query, keep_blank_values=True),
                    headers=dict(self.headers.items()),
                    body=self.rfile.read(length),
                )
                fixture.requests.append(request)
                route = fixture._routes.get((request.method, request.path))
                if route is None and request.path == "organizations":
                    response = SocketResponse(
                        200,
                        {"organizations": {"org-fixture": {"slug": "fixture-org"}}},
                    )
                elif route is None:
                    response = SocketResponse(404, {"error": {"message": "Not found"}})
                else:
                    response = route(request)
                body = response.raw_body
                if body is None:
                    body = json.dumps(response.payload).encode("utf-8")
                self.send_response(response.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *args: object) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


def socket_api_fixture() -> SocketApiFixture:
    fixture = SocketApiFixture()
    fixture.start()
    return fixture
