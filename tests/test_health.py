from __future__ import annotations


def test_dashboard_is_served_with_security_headers(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "API Sentinel" in response.text
    assert 'src="/static/app.js"' in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_static_assets_are_served(client):
    css = client.get("/static/styles.css")
    js = client.get("/static/app.js")

    assert css.status_code == 200
    assert "text/css" in css.headers["content-type"]
    assert js.status_code == 200
    assert "javascript" in js.headers["content-type"]


def test_health_endpoint(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "API Sentinel"
    assert data["version"]
    assert data["ssrf_protection"] == "enabled"
    assert data["loopback_scanning"] == "disabled"
    assert data["utc_time"].endswith("Z")
    assert response.headers["cache-control"] == "no-store"


def test_demo_endpoint_is_predictable_and_offline(client):
    response = client.get("/api/demo")

    assert response.status_code == 200
    data = response.json()
    assert data["demo"] is True
    assert data["report_id"] == "demo-0001"
    assert data["scanned_at"] == "2026-01-15T12:00:00Z"
    assert data["target_url"] == "http://demo.api-sentinel.test:8080/v1/orders"
    assert data["reachable"] is True
    assert data["http_status"] == 200
    assert data["application_ok"] is True
    assert data["risk_score"] == 40
    assert data["risk_level"] == "high"
    assert data["error"] is None

    finding_ids = {finding["id"] for finding in data["findings"]}
    assert finding_ids == {
        "transport.plaintext_http",
        "headers.csp_missing",
        "headers.referrer_policy_missing",
    }
    assert sum(finding["weight"] for finding in data["findings"]) == data["risk_score"]
    assert any("No outbound request" in item for item in data["limitations"])
    assert data["risk_model"]["weights"]["high"] == 25


def test_unknown_route_returns_404(client):
    response = client.get("/definitely-not-a-route")
    assert response.status_code == 404
