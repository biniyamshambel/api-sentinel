from __future__ import annotations

from app.demo import build_demo_report
from app.models import Finding, RiskLevel, Severity
from app.network import FetchFailureInfo, FetchResult, RedirectProblem
from app.scanner import SEVERITY_WEIGHTS, build_report, calculate_risk
from tests.helpers import make_settings

SECURE_HEADERS = {
    "content-type": "application/json",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
}


def make_fetch(
    *,
    url: str = "https://api.example.com/health",
    status: int = 200,
    headers: dict[str, str] | None = None,
    elapsed_ms: float = 120.0,
    error: FetchFailureInfo | None = None,
    redirect_problem: RedirectProblem | None = None,
    body_truncated: bool = False,
) -> FetchResult:
    return FetchResult(
        requested_url=url,
        final_url=None if error is not None else url,
        status_code=status if error is None else None,
        reason=None if error is not None else ("OK" if status == 200 else "Status"),
        headers=SECURE_HEADERS if headers is None else headers,
        elapsed_ms=elapsed_ms,
        chain=(url,),
        body_bytes=2,
        body_truncated=body_truncated,
        redirect_problem=redirect_problem,
        error=error,
    )


def test_secure_https_configuration_scores_zero():
    report = build_report(make_fetch(), make_settings())

    assert report.reachable is True
    assert report.application_ok is True
    assert report.risk_score == 0
    assert report.risk_level == RiskLevel.low
    assert report.findings == []
    assert all(check.status.value == "pass" for check in report.checks)


def test_missing_headers_produce_findings_evidence_and_score():
    report = build_report(make_fetch(headers={}), make_settings())

    by_id = {finding.id: finding for finding in report.findings}
    assert set(by_id) == {
        "headers.hsts_missing",
        "headers.x_content_type_options_missing",
        "headers.csp_missing",
        "headers.referrer_policy_missing",
    }
    assert report.risk_score == 30
    assert report.risk_level == RiskLevel.moderate
    assert sum(finding.weight for finding in report.findings) == 30
    assert all("not present" in finding.evidence for finding in report.findings)
    assert all(finding.recommendation for finding in report.findings)


def test_plaintext_http_is_high_severity_and_hsts_is_not_applicable():
    headers = {key: value for key, value in SECURE_HEADERS.items() if key != "strict-transport-security"}
    report = build_report(
        make_fetch(url="http://api.example.com/health", headers=headers),
        make_settings(),
    )

    by_id = {finding.id: finding for finding in report.findings}
    assert "transport.plaintext_http" in by_id
    assert by_id["transport.plaintext_http"].severity == Severity.high
    assert "headers.hsts_missing" not in by_id
    hsts_check = next(check for check in report.checks if check.id == "header_hsts")
    assert hsts_check.status.value == "not_applicable"
    assert report.risk_score == 25
    assert report.risk_level == RiskLevel.moderate


def test_hsts_short_max_age_is_a_low_finding():
    headers = dict(SECURE_HEADERS)
    headers["strict-transport-security"] = "max-age=3600"
    report = build_report(make_fetch(headers=headers), make_settings())

    finding = next(item for item in report.findings if item.id == "headers.hsts_short_max_age")
    assert finding.severity == Severity.low
    assert "3600" in finding.evidence


def test_hsts_disabled_is_a_medium_finding():
    headers = dict(SECURE_HEADERS)
    headers["strict-transport-security"] = "max-age=0"
    report = build_report(make_fetch(headers=headers), make_settings())

    finding = next(item for item in report.findings if item.id == "headers.hsts_disabled")
    assert finding.severity == Severity.medium


def test_hsts_without_max_age_is_a_low_finding():
    headers = dict(SECURE_HEADERS)
    headers["strict-transport-security"] = "includeSubDomains"
    report = build_report(make_fetch(headers=headers), make_settings())

    assert any(item.id == "headers.hsts_no_max_age" for item in report.findings)


def test_weak_header_values_are_detected():
    headers = dict(SECURE_HEADERS)
    headers["x-content-type-options"] = "sniff"
    headers["content-security-policy"] = "default-src 'self'; script-src 'unsafe-inline'"
    headers["referrer-policy"] = "unsafe-url"
    report = build_report(make_fetch(headers=headers), make_settings())

    ids = {finding.id for finding in report.findings}
    assert "headers.x_content_type_options_invalid" in ids
    assert "headers.csp_unsafe_directives" in ids
    assert "headers.referrer_policy_unsafe" in ids
    assert report.risk_score == 15


def test_client_error_keeps_target_reachable_but_not_successful():
    report = build_report(make_fetch(status=404, headers=SECURE_HEADERS), make_settings())

    assert report.reachable is True
    assert report.application_ok is False
    assert report.http_status == 404
    finding = next(item for item in report.findings if item.id == "http.non_success_status")
    assert finding.severity == Severity.medium
    assert report.risk_score == 10


def test_server_error_is_high_severity():
    report = build_report(make_fetch(status=503, headers=SECURE_HEADERS), make_settings())

    finding = next(item for item in report.findings if item.id == "http.non_success_status")
    assert finding.severity == Severity.high
    assert report.application_ok is False
    assert report.risk_score == 25


def test_elevated_and_very_slow_latency_findings():
    warned = build_report(make_fetch(elapsed_ms=1500), make_settings())
    failed = build_report(make_fetch(elapsed_ms=4200), make_settings())

    warn_finding = next(item for item in warned.findings if item.id == "performance.elevated_latency")
    fail_finding = next(item for item in failed.findings if item.id == "performance.slow_response")
    assert warn_finding.severity == Severity.low
    assert fail_finding.severity == Severity.medium


def test_timeout_report_is_unreachable_and_has_no_response_time():
    fetch = make_fetch(
        status=0,
        error=FetchFailureInfo("timeout", "The target did not respond within 8 seconds."),
    )
    report = build_report(fetch, make_settings())

    assert report.reachable is False
    assert report.http_status is None
    assert report.application_ok is None
    assert report.response_time_ms is None
    assert report.risk_score == 25
    assert report.findings[0].id == "availability.target_unreachable"
    assert report.error is not None
    assert report.error.code == "timeout"
    assert any("No HTTP response" in limitation for limitation in report.limitations)


def test_blocked_destination_is_critical():
    fetch = make_fetch(
        status=0,
        error=FetchFailureInfo(
            "blocked_destination", "The connection was blocked because the destination is not permitted."
        ),
    )
    report = build_report(fetch, make_settings())

    assert report.findings[0].severity == Severity.critical
    assert report.risk_score == 40
    assert report.risk_level == RiskLevel.high


def test_blocked_redirect_is_reported():
    problem = RedirectProblem("blocked", "http://169.254.169.254/", "Blocked destination.")
    report = build_report(
        make_fetch(status=302, redirect_problem=problem),
        make_settings(),
    )

    finding = next(item for item in report.findings if item.id == "redirect.blocked")
    assert finding.severity == Severity.high
    assert report.redirect_problem is not None
    assert report.redirect_problem.kind == "blocked"
    assert any("redirect was not followed" in item for item in report.limitations)


def test_redirect_limit_problem_is_medium():
    problem = RedirectProblem("too_many", "https://api.example.com/loop", "Redirect limit reached.")
    report = build_report(make_fetch(status=302, redirect_problem=problem), make_settings())

    finding = next(item for item in report.findings if item.id == "redirect.too_many")
    assert finding.severity == Severity.medium


def test_risk_score_is_capped_and_bands_are_explicit():
    def finding(severity: Severity) -> Finding:
        return Finding(
            id=f"test.{severity.value}",
            title="test",
            severity=severity,
            category="test",
            description="test",
            evidence="test",
            recommendation="test",
            weight=SEVERITY_WEIGHTS[severity],
        )

    assert calculate_risk([]) == (0, RiskLevel.low)
    assert calculate_risk([finding(Severity.high)]) == (25, RiskLevel.moderate)
    assert calculate_risk([finding(Severity.critical)]) == (40, RiskLevel.high)
    assert calculate_risk([finding(Severity.critical)] * 3) == (100, RiskLevel.critical)
    assert SEVERITY_WEIGHTS[Severity.info] == 0


def test_report_structure_and_transparency_fields():
    report = build_report(make_fetch(headers={}), make_settings())

    assert report.scanner_version
    assert report.rule_version
    assert report.scanned_at.endswith("Z")
    assert report.target_url == "https://api.example.com/health"
    assert report.final_url == report.target_url
    assert report.redirect_chain == [report.target_url]
    assert report.redirect_count == 0
    assert report.risk_model.weights["critical"] == 40
    assert report.risk_model.bands["critical"] == "60-100"
    assert "not a validated" in report.risk_model.disclaimer
    assert len(report.limitations) >= 5
    assert report.demo is False


def test_truncated_response_is_disclosed():
    report = build_report(make_fetch(body_truncated=True), make_settings())
    assert any("capped at" in limitation for limitation in report.limitations)
    assert report.response_truncated is True


def test_demo_report_uses_scanner_formula_and_fixed_identity():
    report = build_demo_report(make_settings())

    assert report.demo is True
    assert report.report_id == "demo-0001"
    assert report.risk_score == sum(finding.weight for finding in report.findings)
    assert report.risk_level in {RiskLevel.low, RiskLevel.moderate, RiskLevel.high, RiskLevel.critical}
