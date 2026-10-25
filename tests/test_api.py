from __future__ import annotations

import httpx
import pytest

from main import app, get_fetcher
from tests.helpers import make_settings, mock_fetcher

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'",
    "Referrer-Policy": "no-referrer",
}


def install_fetcher(fetcher) -> None:
    app.dependency_overrides[get_fetcher] = lambda: fetcher


def test_scan_endpoint_returns_structured_report(client):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=SECURE_HEADERS, json={"ok": True}, request=request)

    settings = make_settings()
    install_fetcher(mock_fetcher(settings, handler))

    response = client.post(
        "/api/scan", json={"url": "https://api.example.com/health"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["target_url"] == "https://api.example.com/health"
    assert data["reachable"] is True
    assert data["http_status"] == 200
    assert data["application_ok"] is True
    assert data["risk_score"] == 0
    assert data["risk_level"] == "low"
    assert data["findings"] == []
    assert isinstance(data["response_time_ms"], (int, float))
    assert data["demo"] is False
    assert data["error"] is None
    assert data["redirect_chain"] == ["https://api.example.com/health"]
    assert response.headers["cache-control"] == "no-store"


def test_scan_endpoint_handles_http_500_as_reachable_but_not_successful(client):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, headers=SECURE_HEADERS, text="boom", request=request)

    install_fetcher(mock_fetcher(make_settings(), handler))
    response = client.post("/api/scan", json={"url": "https://api.example.com/health"})

    assert response.status_code == 200
    data = response.json()
    assert data["reachable"] is True
    assert data["application_ok"] is False
    assert data["http_status"] == 500
    assert data["risk_score"] == 25
    assert data["error"] is None


def test_scan_endpoint_reports_connection_failure_without_crashing(client):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    install_fetcher(mock_fetcher(make_settings(), handler))
    response = client.post("/api/scan", json={"url": "https://api.example.com/health"})

    assert response.status_code == 200
    data = response.json()
    assert data["reachable"] is False
    assert data["http_status"] is None
    assert data["application_ok"] is None
    assert data["response_time_ms"] is None
    assert data["error"]["code"] == "connection_failed"
    assert data["findings"][0]["id"] == "availability.target_unreachable"


def test_scan_endpoint_reports_timeout_safely(client):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    install_fetcher(mock_fetcher(make_settings(timeout=0.5), handler))
    response = client.post("/api/scan", json={"url": "https://api.example.com/health"})

    assert response.status_code == 200
    data = response.json()
    assert data["reachable"] is False
    assert data["error"]["code"] == "timeout"
    assert "0.5" in data["error"]["message"]


@pytest.mark.parametrize(
    ("url", "expected_code"),
    [
        ("ftp://example.com/file", "invalid_scheme"),
        ("https://user:pass@example.com/", "credentials_not_allowed"),
        ("http://example.com:22/", "port_not_allowed"),
        ("http://127.0.0.1:8001/", "blocked_destination"),
        ("http://10.0.0.9/", "blocked_destination"),
        ("http://169.254.169.254/latest/meta-data/", "blocked_destination"),
    ],
)
def test_scan_endpoint_rejects_disallowed_targets(client, url, expected_code):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("No outbound request should be attempted")

    install_fetcher(mock_fetcher(make_settings(), handler))
    response = client.post("/api/scan", json={"url": url})

    assert response.status_code == 422
    data = response.json()
    assert data["code"] == expected_code
    assert isinstance(data["detail"], str)
    assert data["detail"]


def test_scan_endpoint_rejects_hostname_resolving_to_private_address(client):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("No outbound request should be attempted")

    install_fetcher(
        mock_fetcher(
            make_settings(),
            handler,
            mapping={"internal.example.com": "10.0.0.7"},
        )
    )
    response = client.post("/api/scan", json={"url": "https://internal.example.com/"})

    assert response.status_code == 422
    assert response.json()["code"] == "blocked_destination"


def test_scan_endpoint_rejects_empty_and_missing_url(client):
    empty = client.post("/api/scan", json={"url": "   "})
    missing = client.post("/api/scan", json={})

    assert empty.status_code == 422
    assert missing.status_code == 422


def test_scan_endpoint_does_follow_public_redirects_but_blocks_private_ones(client):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(
                302,
                headers={"Location": "http://169.254.169.254/latest/meta-data/"},
                request=request,
            )
        raise AssertionError("Blocked redirect must not be requested")

    install_fetcher(mock_fetcher(make_settings(), handler))
    response = client.post("/api/scan", json={"url": "https://api.example.com/start"})

    assert response.status_code == 200
    data = response.json()
    assert data["reachable"] is True
    assert data["http_status"] == 302
    assert data["application_ok"] is False
    assert data["redirect_problem"]["kind"] == "blocked"
    assert any(finding["id"] == "redirect.blocked" for finding in data["findings"])
