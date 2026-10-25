"""Deterministic sample report for local demonstrations and UI development."""

from __future__ import annotations

from .config import Settings
from .network import FetchResult
from .scanner import build_report
from .models import ScanReport

_DEMO_TIME = "2026-01-15T12:00:00Z"


def build_demo_report(settings: Settings | None = None) -> ScanReport:
    settings = settings or Settings()
    fetch = FetchResult(
        requested_url="http://demo.api-sentinel.test:8080/v1/orders",
        final_url="http://demo.api-sentinel.test:8080/v1/orders",
        status_code=200,
        reason="OK",
        headers={
            "content-type": "application/json",
            "x-content-type-options": "nosniff",
            "server": "demo-target/1.0",
        },
        elapsed_ms=184.2,
        chain=("http://demo.api-sentinel.test:8080/v1/orders",),
        body_bytes=96,
        body_truncated=False,
    )
    return build_report(
        fetch,
        settings,
        scanned_at=_DEMO_TIME,
        report_id="demo-0001",
        demo=True,
        extra_limitations=(
            "The sample target name uses the reserved .test domain and does not resolve.",
        ),
    )
