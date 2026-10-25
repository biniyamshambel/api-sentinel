"""Pydantic models used by the API and the downloadable report format."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .config import MAX_URL_LENGTH


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class RiskLevel(str, Enum):
    low = "low"
    moderate = "moderate"
    high = "high"
    critical = "critical"


class CheckStatus(str, Enum):
    passed = "pass"
    warning = "warn"
    failed = "fail"
    not_applicable = "not_applicable"
    unknown = "unknown"


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str
    recommendation: str
    weight: int = Field(ge=0, description="Contribution to the additive risk score")


class CheckResult(BaseModel):
    id: str
    label: str
    status: CheckStatus
    detail: str


class RedirectProblemInfo(BaseModel):
    kind: Literal["blocked", "too_many", "invalid"]
    location: str
    message: str


class ErrorInfo(BaseModel):
    code: str
    message: str


class RiskModel(BaseModel):
    method: str
    weights: dict[str, int]
    bands: dict[str, str]
    disclaimer: str


class ScanReport(BaseModel):
    report_id: str
    scanner_version: str
    rule_version: str
    target_url: str
    final_url: str | None
    scanned_at: str = Field(description="UTC timestamp in ISO 8601 format")
    reachable: bool
    http_status: int | None
    http_reason: str | None
    application_ok: bool | None = Field(
        default=None,
        description="True only for a 2xx application response; an HTTP response alone is not success.",
    )
    response_time_ms: float | None
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    findings: list[Finding]
    checks: list[CheckResult]
    redirect_chain: list[str]
    redirect_count: int
    redirect_problem: RedirectProblemInfo | None = None
    body_bytes_read: int
    response_truncated: bool
    demo: bool = False
    limitations: list[str]
    error: ErrorInfo | None
    risk_model: RiskModel


class ScanRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=MAX_URL_LENGTH,
        description="Public http:// or https:// URL to assess",
        examples=["https://api.example.com/health"],
    )

    @field_validator("url")
    @classmethod
    def _trim_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Please enter a URL to scan.")
        return value


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    version: str
    utc_time: str
    ssrf_protection: Literal["enabled"]
    loopback_scanning: str
