from __future__ import annotations

import copy
import re
from datetime import datetime, timezone

import pytest

from app.config import Settings
from app.demo import build_demo_report
from app.models import RiskLevel, Severity
from app.pdf_report import (
    MAX_FINDINGS,
    build_pdf,
    pdf_filename,
    redact_url,
)
from main import MAX_PDF_REQUEST_BYTES


def _report():
    return build_demo_report(Settings())


def _page_count(pdf: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page(?!s)", pdf))


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def test_pdf_endpoint_returns_downloadable_report(client):
    demo = client.get("/api/demo").json()

    response = client.post("/api/report/pdf", json=demo)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == (
        'attachment; filename="api-sentinel-report-2026-01-15.pdf"'
    )
    assert response.headers["content-length"] == str(len(response.content))
    assert response.content.startswith(b"%PDF-")
    assert response.content.rstrip().endswith(b"%%EOF")
    assert _page_count(response.content) >= 1
    assert b"Biniyam Shambel" in response.content


def test_pdf_endpoint_rejects_html_and_empty_payloads(client):
    html = client.post(
        "/api/report/pdf",
        content=b"<html><body>not a report</body></html>",
        headers={"content-type": "application/json"},
    )
    empty = client.post("/api/report/pdf", content=b"")

    assert html.status_code == 422
    assert html.json()["code"] == "invalid_report"
    assert empty.status_code == 422
    assert empty.json()["code"] == "invalid_report"


def test_pdf_endpoint_rejects_oversized_payload(client):
    response = client.post(
        "/api/report/pdf",
        content=b"x" * (MAX_PDF_REQUEST_BYTES + 1),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["code"] == "report_too_large"


def test_pdf_endpoint_rejects_unbounded_finding_counts(client):
    demo = client.get("/api/demo").json()
    demo["findings"] = [copy.deepcopy(demo["findings"][0]) for _ in range(MAX_FINDINGS + 1)]

    response = client.post("/api/report/pdf", json=demo)

    assert response.status_code == 422
    assert response.json()["code"] == "invalid_report"


def test_pdf_handles_zero_findings():
    report = _report().model_copy(
        update={"findings": [], "risk_score": 0, "risk_level": RiskLevel.low}
    )

    pdf = build_pdf(report, compress=False)

    assert pdf.startswith(b"%PDF-")
    assert b"No findings were recorded" in pdf
    assert b"Created by Biniyam Shambel" in pdf
    assert b"Ethical Hacker | ID-CTC_721" in pdf
    assert _page_count(pdf) >= 1


def test_pdf_handles_many_findings_across_pages():
    source = _report().findings[0]
    findings = [
        source.model_copy(
            update={
                "id": f"long.{index}",
                "title": f"Long finding {index + 1:02d}: " + ("header hardening review " * 12),
                "description": "A detailed explanation. " * 40,
                "evidence": "evidence line with & <special> characters " * 20,
                "recommendation": "Apply the documented remediation. " * 30,
            }
        )
        for index in range(25)
    ]
    report = _report().model_copy(update={"findings": findings})

    pdf = build_pdf(report, compress=False)

    assert pdf.startswith(b"%PDF-")
    assert _page_count(pdf) >= 2
    assert b"1. Long finding 1" in pdf
    assert b"25. Long finding 25" in pdf


def test_pdf_handles_unicode_and_special_characters():
    source = _report().findings[0]
    finding = source.model_copy(
        update={
            "title": "Unicode façade — 日本語 — 🔒",
            "description": "Beschreibung mit ünïcode, <script>alert('x')</script> & symbols.",
            "evidence": "Header: välue <tag> & more",
            "recommendation": "Исправьте конфигурацию. 🚀",
        }
    )
    report = _report().model_copy(
        update={
            "target_url": "https://例え.テスト/路径?ключ=значение",
            "final_url": "https://例え.テスト/路径?ключ=значение",
            "findings": [finding],
        }
    )

    pdf = build_pdf(report, compress=False)

    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert _page_count(pdf) >= 1


def test_pdf_redacts_query_values_and_credentials():
    report = _report().model_copy(
        update={
            "target_url": "https://user:pass@api.example.com/v1?token=SUPERSECRET&x=1#frag",
            "final_url": "https://user:pass@api.example.com/v1?token=SUPERSECRET&x=1#frag",
        }
    )

    pdf = build_pdf(report, compress=False)

    assert b"SUPERSECRET" not in pdf
    assert b"user:pass" not in pdf
    assert b"REDACTED" in pdf
    assert redact_url(report.target_url) == (
        "https://api.example.com/v1?token=REDACTED&x=REDACTED"
    )


def test_pdf_redacts_urls_inside_finding_text():
    source = _report().findings[0]
    finding = source.model_copy(
        update={
            "evidence": (
                "Redirect target: https://api.example.com/v1?token=SUPERSECRET&x=1#frag"
            ),
            "description": "See https://api.example.com/v1?key=SUPERSECRET for context.",
        }
    )
    report = _report().model_copy(update={"findings": [finding]})

    pdf = build_pdf(report, compress=False)

    assert b"SUPERSECRET" not in pdf
    assert b"REDACTED" in pdf


def test_pdf_filename_uses_report_date():
    assert pdf_filename(_report()) == "api-sentinel-report-2026-01-15.pdf"

    fallback = _report().model_copy(update={"scanned_at": "not-a-date"})
    assert pdf_filename(fallback) == f"api-sentinel-report-{_stamp()}.pdf"


def test_pdf_renders_unreachable_report_without_inventing_headers():
    report = _report().model_copy(
        update={
            "reachable": False,
            "http_status": None,
            "http_reason": None,
            "application_ok": None,
            "response_time_ms": None,
            "checks": [],
            "findings": [],
            "risk_score": 0,
            "risk_level": RiskLevel.low,
        }
    )

    pdf = build_pdf(report, compress=False)

    assert pdf.startswith(b"%PDF-")
    assert b"could not obtain an HTTP response" in pdf
    assert b"No check details were returned" in pdf


@pytest.mark.parametrize("severity", list(Severity))
def test_pdf_supports_every_severity(severity):
    source = _report().findings[0]
    report = _report().model_copy(
        update={"findings": [source.model_copy(update={"severity": severity})]}
    )

    pdf = build_pdf(report, compress=False)

    assert pdf.startswith(b"%PDF-")


def test_pdf_does_not_scan_a_target(monkeypatch):
    """The endpoint must only render supplied data and never call the network layer."""

    from app.network import SafeFetcher

    async def fail_fetch(self, _url):  # pragma: no cover - assertion guard
        raise AssertionError("PDF generation must not perform a network request")

    monkeypatch.setattr(SafeFetcher, "fetch", fail_fetch)

    from fastapi.testclient import TestClient
    from main import app

    with TestClient(app) as client:
        demo = client.get("/api/demo").json()
        response = client.post("/api/report/pdf", json=demo)

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")
