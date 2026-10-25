from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from fastapi.testclient import TestClient
import pytest

from app.config import Settings
from app.network import SafeFetcher
from main import app, get_fetcher, get_settings
from tests.helpers import make_settings


class _DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: object) -> None:  # noqa: A003
        return

    def _respond(
        self, status: int, body: bytes = b"", headers: dict[str, str] | None = None
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/ok":
            self._respond(
                200,
                b'{"status":"ok"}',
                {
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "default-src 'none'",
                    "Referrer-Policy": "no-referrer",
                    "Strict-Transport-Security": "max-age=31536000",
                },
            )
        elif path == "/insecure":
            self._respond(200, b'{"status":"ok"}')
        elif path == "/error":
            self._respond(500, b'{"error":"boom"}')
        elif path == "/redirect":
            self._respond(302, b"", {"Location": "/ok"})
        elif path == "/redirect-private":
            self._respond(
                302,
                b"",
                {"Location": "http://169.254.169.254/latest/meta-data/"},
            )
        elif path == "/redirect-loop":
            self._respond(302, b"", {"Location": "/redirect-loop"})
        elif path == "/slow":
            time.sleep(0.9)
            self._respond(200, b'{"slow":true}')
        elif path == "/large":
            self._respond(200, b"x" * 5000)
        else:
            self._respond(404, b'{"error":"not found"}')


@pytest.fixture()
def local_server() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DemoHandler)
    server.daemon_threads = True
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture()
def loopback_settings(local_server: int) -> Settings:
    return make_settings(
        allow_loopback=True,
        ports=frozenset({local_server}),
        timeout=2.0,
        max_body_bytes=512,
    )


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        try:
            yield test_client
        finally:
            app.dependency_overrides.clear()


@pytest.fixture()
def default_settings() -> Settings:
    return make_settings()


@pytest.fixture(autouse=True)
def _clean_overrides(default_settings: Settings):
    app.dependency_overrides[get_settings] = lambda: default_settings
    yield
    app.dependency_overrides.pop(get_settings, None)
    app.dependency_overrides.pop(get_fetcher, None)


def override_fetcher(fetcher: SafeFetcher) -> None:
    app.dependency_overrides[get_fetcher] = lambda: fetcher
