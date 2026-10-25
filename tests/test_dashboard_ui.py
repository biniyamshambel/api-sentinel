from __future__ import annotations

import re


def _dashboard(client) -> str:
    response = client.get("/")
    assert response.status_code == 200
    return response.text


def test_dashboard_contains_required_creator_attribution(client):
    html = _dashboard(client)

    assert "Created by Biniyam Shambel" in html
    assert "Ethical Hacker | ID-CTC_721" in html


def test_dashboard_exposes_scan_and_export_controls(client):
    html = _dashboard(client)

    assert 'id="scan-form"' in html
    assert "Run Security Scan" in html
    assert 'type="submit"' in html
    assert 'id="pdf-button"' in html
    assert "Download PDF Report" in html
    assert 'id="download-button"' in html
    assert "Download JSON Report" in html
    assert 'id="export-status"' in html
    assert "No assessment loaded yet" in html


def test_dashboard_contains_required_sections_and_guidance(client):
    html = _dashboard(client)

    for section in (
        "Latest scan overview",
        "Latest scan status",
        "HTTP status",
        "Response latency",
        "Total findings",
        "Security score",
        "Findings",
        "Checks performed",
        "Score model",
        "Understanding your results",
        "About the project",
    ):
        assert section in html

    assert "API Sentinel is an API health monitoring and security configuration" in html
    assert "scan only systems that you own or have" in html
    assert "explicit permission to test" in html
    assert "not a penetration test" in html.lower()


def test_dashboard_marks_sample_and_temporary_history(client):
    html = _dashboard(client)

    assert "Sample data" in html
    assert "Load sample report" in html
    assert "Temporary browser history for this tab only." in html
    assert "Query strings are removed" in html
    assert "cleared when this tab closes" in html


def test_dashboard_uses_warm_palette_and_reduced_motion_styles(client):
    css = client.get("/static/styles.css").text.lower()

    for token in ("#faf8f5", "#6f4e37", "#3b2a20", "#292522", "#716961"):
        assert token in css

    assert "prefers-reduced-motion" in css
    assert ":focus-visible" in css


def test_dashboard_javascript_uses_same_report_for_exports_and_no_html_injection(client):
    js = client.get("/static/app.js").text

    assert '"/api/report/pdf"' in js
    assert '"/api/scan"' in js
    assert "JSON.stringify(state.report)" in js
    assert "sessionStorage" in js
    assert not re.search(r"\.innerHTML\s*=", js)
    assert re.search(r"body:\s*JSON\.stringify\(state\.report\)", js)
