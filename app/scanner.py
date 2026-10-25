"""Explainable, rule-based HTTP security configuration assessment."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlsplit

from .config import RULE_VERSION, VERSION, Settings
from .models import (
    CheckResult,
    CheckStatus,
    ErrorInfo,
    Finding,
    RedirectProblemInfo,
    RiskLevel,
    RiskModel,
    ScanReport,
    Severity,
)
from .network import FetchResult

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.critical: 40,
    Severity.high: 25,
    Severity.medium: 10,
    Severity.low: 5,
    Severity.info: 0,
}

RISK_BANDS = (
    (60, RiskLevel.critical),
    (35, RiskLevel.high),
    (10, RiskLevel.moderate),
    (0, RiskLevel.low),
)

RISK_MODEL = RiskModel(
    method=(
        "Transparent additive rubric: each finding contributes its severity weight; "
        "the total is capped at 100."
    ),
    weights={severity.value: weight for severity, weight in SEVERITY_WEIGHTS.items()},
    bands={
        "low": "0-9",
        "moderate": "10-34",
        "high": "35-59",
        "critical": "60-100",
    },
    disclaimer=(
        "This is a project-defined prioritisation aid, not a validated "
        "industry-standard risk rating and not proof of exploitability."
    ),
)

_HSTS_MIN_AGE = 15_552_000  # 180 days
_SLOW_WARN_MS = 1_000.0
_SLOW_FAIL_MS = 3_000.0


def calculate_risk(findings: Iterable[Finding]) -> tuple[int, RiskLevel]:
    score = min(100, sum(SEVERITY_WEIGHTS[finding.severity] for finding in findings))
    for threshold, level in RISK_BANDS:
        if score >= threshold:
            return score, level
    return 0, RiskLevel.low


def _safe_text(value: str | None, limit: int = 300) -> str:
    if value is None:
        return "not present"
    cleaned = "".join(char if char.isprintable() else "?" for char in value)
    return cleaned[:limit] + ("..." if len(cleaned) > limit else "")


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: Severity,
    category: str,
    description: str,
    evidence: str,
    recommendation: str,
) -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        weight=SEVERITY_WEIGHTS[severity],
    )


def _unreachable(fetch: FetchResult) -> tuple[list[Finding], list[CheckResult]]:
    error = fetch.error
    code = error.code if error else "unknown"
    message = error.message if error else "No response was received."

    if code == "blocked_destination":
        severity = Severity.critical
        description = (
            "The destination passed initial URL validation but the connection layer "
            "blocked the resolved address. This can indicate DNS rebinding or a "
            "misdirected redirect."
        )
    elif code == "timeout":
        severity = Severity.high
        description = "The target did not return an HTTP response within the configured timeout."
    elif code == "tls_error":
        severity = Severity.high
        description = "A TLS connection could not be established or the certificate was rejected."
    else:
        severity = Severity.high
        description = "No HTTP response was received, so header checks could not be performed."

    finding = _finding(
        finding_id="availability.target_unreachable",
        title="Target did not return a usable HTTP response",
        severity=severity,
        category="Availability",
        description=description,
        evidence=f"{code}: {_safe_text(message)}",
        recommendation=(
            "Confirm the URL, DNS records, service availability, firewall rules, and "
            "TLS certificate. Re-run the scan once the endpoint is reachable."
        ),
    )
    check = CheckResult(
        id="availability",
        label="Target reachability",
        status=CheckStatus.failed,
        detail=message,
    )
    return [finding], [check]


def _assess_transport(
    final_url: str, findings: list[Finding], checks: list[CheckResult]
) -> str:
    scheme = urlsplit(final_url).scheme.lower()
    if scheme == "https":
        checks.append(
            CheckResult(
                id="transport_encryption",
                label="Encrypted transport (HTTPS)",
                status=CheckStatus.passed,
                detail="The final response was received over HTTPS.",
            )
        )
    else:
        findings.append(
            _finding(
                finding_id="transport.plaintext_http",
                title="API is served over plaintext HTTP",
                severity=Severity.high,
                category="Transport security",
                description=(
                    "The final response was received over HTTP. Traffic can be read or "
                    "modified by anyone on the network path, including credentials and tokens."
                ),
                evidence=f"Final URL scheme: {scheme or 'unknown'}",
                recommendation=(
                    "Serve the API exclusively over HTTPS with a valid certificate and "
                    "redirect HTTP requests to HTTPS."
                ),
            )
        )
        checks.append(
            CheckResult(
                id="transport_encryption",
                label="Encrypted transport (HTTPS)",
                status=CheckStatus.failed,
                detail="The final response was received over HTTP.",
            )
        )
    return scheme


def _assess_hsts(
    scheme: str,
    headers: dict[str, str],
    findings: list[Finding],
    checks: list[CheckResult],
) -> None:
    if scheme != "https":
        checks.append(
            CheckResult(
                id="header_hsts",
                label="Strict-Transport-Security (HSTS)",
                status=CheckStatus.not_applicable,
                detail="HSTS is only effective and evaluated over HTTPS.",
            )
        )
        return

    value = headers.get("strict-transport-security")
    if value is None:
        findings.append(
            _finding(
                finding_id="headers.hsts_missing",
                title="Strict-Transport-Security header is missing",
                severity=Severity.medium,
                category="Transport security",
                description=(
                    "The HTTPS response does not instruct browsers to use HTTPS for "
                    "future requests. This weakens protection against protocol downgrade "
                    "and cookie-hijacking attacks."
                ),
                evidence="strict-transport-security: not present",
                recommendation=(
                    "Add Strict-Transport-Security with a max-age of at least 15552000 "
                    "seconds (180 days); consider includeSubDomains after confirming all "
                    "subdomains support HTTPS."
                ),
            )
        )
        checks.append(
            CheckResult(
                id="header_hsts",
                label="Strict-Transport-Security (HSTS)",
                status=CheckStatus.failed,
                detail="Header is not present on the HTTPS response.",
            )
        )
        return

    match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if match is None:
        findings.append(
            _finding(
                finding_id="headers.hsts_no_max_age",
                title="HSTS header does not define a usable max-age",
                severity=Severity.low,
                category="Transport security",
                description="Without max-age, the HSTS directive is ignored by browsers.",
                evidence=f"strict-transport-security: {_safe_text(value)}",
                recommendation="Define max-age (for example, max-age=31536000) in the HSTS header.",
            )
        )
        checks.append(
            CheckResult(
                id="header_hsts",
                label="Strict-Transport-Security (HSTS)",
                status=CheckStatus.warning,
                detail="Header is present but max-age is missing or malformed.",
            )
        )
        return

    max_age = int(match.group(1))
    if max_age == 0:
        findings.append(
            _finding(
                finding_id="headers.hsts_disabled",
                title="HSTS is explicitly disabled with max-age=0",
                severity=Severity.medium,
                category="Transport security",
                description="A max-age of zero tells browsers to forget the HSTS policy.",
                evidence=f"strict-transport-security: {_safe_text(value)}",
                recommendation="Use a positive max-age, ideally one year or more.",
            )
        )
        checks.append(
            CheckResult(
                id="header_hsts",
                label="Strict-Transport-Security (HSTS)",
                status=CheckStatus.failed,
                detail="HSTS is present but disabled with max-age=0.",
            )
        )
    elif max_age < _HSTS_MIN_AGE:
        findings.append(
            _finding(
                finding_id="headers.hsts_short_max_age",
                title="HSTS max-age is shorter than 180 days",
                severity=Severity.low,
                category="Transport security",
                description="A short HSTS lifetime reduces the protection window.",
                evidence=f"strict-transport-security: {_safe_text(value)}",
                recommendation="Use a max-age of at least 15552000 seconds (180 days).",
            )
        )
        checks.append(
            CheckResult(
                id="header_hsts",
                label="Strict-Transport-Security (HSTS)",
                status=CheckStatus.warning,
                detail=f"HSTS max-age is {max_age} seconds (less than 180 days).",
            )
        )
    else:
        checks.append(
            CheckResult(
                id="header_hsts",
                label="Strict-Transport-Security (HSTS)",
                status=CheckStatus.passed,
                detail=f"HSTS is present with max-age={max_age}.",
            )
        )


def _assess_xcto(
    headers: dict[str, str], findings: list[Finding], checks: list[CheckResult]
) -> None:
    value = headers.get("x-content-type-options")
    if value is None:
        findings.append(
            _finding(
                finding_id="headers.x_content_type_options_missing",
                title="X-Content-Type-Options header is missing",
                severity=Severity.low,
                category="Browser hardening",
                description=(
                    "Without nosniff, some browsers may MIME-sniff responses and treat "
                    "content as a different type than declared."
                ),
                evidence="x-content-type-options: not present",
                recommendation="Return X-Content-Type-Options: nosniff on API responses.",
            )
        )
        checks.append(
            CheckResult(
                id="header_xcto",
                label="X-Content-Type-Options",
                status=CheckStatus.failed,
                detail="Header is not present.",
            )
        )
        return

    if value.strip().lower() == "nosniff":
        checks.append(
            CheckResult(
                id="header_xcto",
                label="X-Content-Type-Options",
                status=CheckStatus.passed,
                detail="Header is set to nosniff.",
            )
        )
    else:
        findings.append(
            _finding(
                finding_id="headers.x_content_type_options_invalid",
                title="X-Content-Type-Options does not use the nosniff directive",
                severity=Severity.low,
                category="Browser hardening",
                description="Unexpected values do not enable MIME-sniffing protection.",
                evidence=f"x-content-type-options: {_safe_text(value)}",
                recommendation="Set the header to the exact value nosniff.",
            )
        )
        checks.append(
            CheckResult(
                id="header_xcto",
                label="X-Content-Type-Options",
                status=CheckStatus.warning,
                detail="Header is present but is not set to nosniff.",
            )
        )


def _assess_csp(
    headers: dict[str, str], findings: list[Finding], checks: list[CheckResult]
) -> None:
    value = headers.get("content-security-policy")
    if value is None:
        findings.append(
            _finding(
                finding_id="headers.csp_missing",
                title="Content-Security-Policy header is missing",
                severity=Severity.medium,
                category="Browser hardening",
                description=(
                    "No Content-Security-Policy was returned. CSP is a defence-in-depth "
                    "control that can limit the impact of content injection. Its relevance "
                    "is lower for pure JSON APIs but higher for documentation or browser-facing routes."
                ),
                evidence="content-security-policy: not present",
                recommendation=(
                    "Define a restrictive Content-Security-Policy appropriate to the "
                    "endpoint, especially for any HTML or documentation routes."
                ),
            )
        )
        checks.append(
            CheckResult(
                id="header_csp",
                label="Content-Security-Policy",
                status=CheckStatus.failed,
                detail="Header is not present.",
            )
        )
        return

    lowered = value.lower()
    weak_tokens = [token for token in ("'unsafe-inline'", "'unsafe-eval'") if token in lowered]
    if weak_tokens:
        findings.append(
            _finding(
                finding_id="headers.csp_unsafe_directives",
                title="Content-Security-Policy allows unsafe directives",
                severity=Severity.low,
                category="Browser hardening",
                description=(
                    "The policy contains directives that weaken script or style isolation."
                ),
                evidence=(
                    f"content-security-policy: {_safe_text(value)}; "
                    f"matched: {', '.join(weak_tokens)}"
                ),
                recommendation=(
                    "Remove 'unsafe-inline' and 'unsafe-eval' where possible and use "
                    "nonces or hashes for required inline content."
                ),
            )
        )
        checks.append(
            CheckResult(
                id="header_csp",
                label="Content-Security-Policy",
                status=CheckStatus.warning,
                detail=f"Header is present but contains {', '.join(weak_tokens)}.",
            )
        )
    else:
        checks.append(
            CheckResult(
                id="header_csp",
                label="Content-Security-Policy",
                status=CheckStatus.passed,
                detail="Header is present and no unsafe-inline/unsafe-eval directives were found.",
            )
        )


def _assess_referrer(
    headers: dict[str, str], findings: list[Finding], checks: list[CheckResult]
) -> None:
    value = headers.get("referrer-policy")
    if value is None:
        findings.append(
            _finding(
                finding_id="headers.referrer_policy_missing",
                title="Referrer-Policy header is missing",
                severity=Severity.low,
                category="Browser hardening",
                description=(
                    "The response does not limit referrer information sent to other origins."
                ),
                evidence="referrer-policy: not present",
                recommendation=(
                    "Set Referrer-Policy to a restrictive value such as no-referrer or "
                    "strict-origin-when-cross-origin."
                ),
            )
        )
        checks.append(
            CheckResult(
                id="header_referrer_policy",
                label="Referrer-Policy",
                status=CheckStatus.failed,
                detail="Header is not present.",
            )
        )
        return

    if value.strip().lower() == "unsafe-url":
        findings.append(
            _finding(
                finding_id="headers.referrer_policy_unsafe",
                title="Referrer-Policy permits full URL leakage",
                severity=Severity.low,
                category="Browser hardening",
                description=(
                    "The unsafe-url policy sends the full URL, including path and query "
                    "parameters, to cross-origin destinations."
                ),
                evidence=f"referrer-policy: {_safe_text(value)}",
                recommendation="Use no-referrer or strict-origin-when-cross-origin instead.",
            )
        )
        checks.append(
            CheckResult(
                id="header_referrer_policy",
                label="Referrer-Policy",
                status=CheckStatus.warning,
                detail="Header is set to unsafe-url.",
            )
        )
    else:
        checks.append(
            CheckResult(
                id="header_referrer_policy",
                label="Referrer-Policy",
                status=CheckStatus.passed,
                detail=f"Header is present with value {_safe_text(value, 80)}.",
            )
        )


def _assess_status(
    fetch: FetchResult, findings: list[Finding], checks: list[CheckResult]
) -> None:
    status = fetch.status_code
    if status is None:
        return

    reason = _safe_text(fetch.reason, 80)
    if 200 <= status < 300:
        checks.append(
            CheckResult(
                id="http_status",
                label="Application response status",
                status=CheckStatus.passed,
                detail=f"HTTP {status} {reason}.",
            )
        )
        return

    if 300 <= status < 400:
        if fetch.redirect_problem is None:
            findings.append(
                _finding(
                    finding_id="http.unfollowed_redirect",
                    title=f"Target returned HTTP {status} without a usable redirect",
                    severity=Severity.low,
                    category="Availability",
                    description=(
                        "A redirect response is not a successful API response. No usable "
                        "Location header was available to follow."
                    ),
                    evidence=f"HTTP {status} {reason}",
                    recommendation=(
                        "Return a direct 2xx response for the API endpoint or provide a "
                        "valid redirect to the intended public destination."
                    ),
                )
            )
        checks.append(
            CheckResult(
                id="http_status",
                label="Application response status",
                status=CheckStatus.failed,
                detail=f"HTTP {status} {reason}; a 2xx application response was not received.",
            )
        )
        return

    if 400 <= status < 500:
        severity = Severity.medium
        description = (
            "The target returned a client error. The API is reachable, but the route, "
            "authentication, authorization, or request expectations prevented a "
            "successful application response."
        )
    elif 500 <= status < 600:
        severity = Severity.high
        description = (
            "The target returned a server error. The host is reachable, but the "
            "application failed to process the request."
        )
    else:
        severity = Severity.medium
        description = "The target returned an unexpected HTTP status class."

    findings.append(
        _finding(
            finding_id="http.non_success_status",
            title=f"Target returned HTTP {status}",
            severity=severity,
            category="Availability",
            description=description,
            evidence=f"HTTP {status} {reason}",
            recommendation=(
                "Confirm the endpoint path and required authentication, and investigate "
                "server-side errors. Treat reachability and application success as "
                "separate signals."
            ),
        )
    )
    checks.append(
        CheckResult(
            id="http_status",
            label="Application response status",
            status=CheckStatus.failed,
            detail=f"HTTP {status} {reason}; a 2xx application response was not received.",
        )
    )


def _assess_latency(
    fetch: FetchResult, findings: list[Finding], checks: list[CheckResult]
) -> None:
    elapsed = fetch.elapsed_ms
    if elapsed is None:
        checks.append(
            CheckResult(
                id="latency",
                label="Response time",
                status=CheckStatus.unknown,
                detail="No response timing was available.",
            )
        )
        return

    if elapsed >= _SLOW_FAIL_MS:
        findings.append(
            _finding(
                finding_id="performance.slow_response",
                title="Target response time is very high",
                severity=Severity.medium,
                category="Performance",
                description=(
                    "The measured time to receive the final response headers exceeded "
                    "3 seconds. Slow APIs degrade client experience and can amplify retries."
                ),
                evidence=f"{elapsed:.1f} ms",
                recommendation=(
                    "Investigate server load, database latency, DNS, and network paths; "
                    "consider monitoring response time over time."
                ),
            )
        )
        checks.append(
            CheckResult(
                id="latency",
                label="Response time",
                status=CheckStatus.failed,
                detail=f"{elapsed:.1f} ms (threshold: 3000 ms).",
            )
        )
    elif elapsed >= _SLOW_WARN_MS:
        findings.append(
            _finding(
                finding_id="performance.elevated_latency",
                title="Target response time is elevated",
                severity=Severity.low,
                category="Performance",
                description=(
                    "The measured time to receive the final response headers exceeded "
                    "1 second."
                ),
                evidence=f"{elapsed:.1f} ms",
                recommendation="Review endpoint performance and monitor latency over time.",
            )
        )
        checks.append(
            CheckResult(
                id="latency",
                label="Response time",
                status=CheckStatus.warning,
                detail=f"{elapsed:.1f} ms (warning threshold: 1000 ms).",
            )
        )
    else:
        checks.append(
            CheckResult(
                id="latency",
                label="Response time",
                status=CheckStatus.passed,
                detail=f"{elapsed:.1f} ms (under 1000 ms).",
            )
        )


def _assess_redirect_problem(
    fetch: FetchResult, findings: list[Finding], checks: list[CheckResult]
) -> None:
    problem = fetch.redirect_problem
    if problem is None:
        return

    if problem.kind == "blocked":
        severity = Severity.high
        title = "Redirect to a restricted destination was blocked"
        description = (
            "The target attempted to redirect the scan to an address that is not "
            "permitted by the network safety policy. The redirect was not followed."
        )
    elif problem.kind == "too_many":
        severity = Severity.medium
        title = "Redirect limit was reached"
        description = (
            "The target redirected more times than the configured limit. The last "
            "response was not followed."
        )
    else:
        severity = Severity.low
        title = "A redirect could not be followed"
        description = "The redirect target was not usable."

    findings.append(
        _finding(
            finding_id=f"redirect.{problem.kind}",
            title=title,
            severity=severity,
            category="Redirect safety",
            description=description,
            evidence=f"{_safe_text(problem.location, 500)}: {_safe_text(problem.message)}",
            recommendation=(
                "Review redirect configuration. Redirects should lead to an explicit, "
                "public HTTPS destination and must not be used to reach internal services."
            ),
        )
    )
    checks.append(
        CheckResult(
            id="redirect_safety",
            label="Redirect destination safety",
            status=CheckStatus.failed,
            detail=problem.message,
        )
    )


def assess_fetch(fetch: FetchResult) -> tuple[list[Finding], list[CheckResult]]:
    if fetch.error is not None or fetch.status_code is None:
        return _unreachable(fetch)

    findings: list[Finding] = []
    checks: list[CheckResult] = []
    scheme = _assess_transport(fetch.final_url or fetch.requested_url, findings, checks)

    _assess_hsts(scheme, fetch.headers, findings, checks)
    _assess_xcto(fetch.headers, findings, checks)
    _assess_csp(fetch.headers, findings, checks)
    _assess_referrer(fetch.headers, findings, checks)
    _assess_status(fetch, findings, checks)
    _assess_latency(fetch, findings, checks)
    _assess_redirect_problem(fetch, findings, checks)
    return findings, checks


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_report(
    fetch: FetchResult,
    settings: Settings,
    *,
    scanned_at: str | None = None,
    report_id: str | None = None,
    demo: bool = False,
    extra_limitations: Iterable[str] = (),
) -> ScanReport:
    findings, checks = assess_fetch(fetch)
    score, level = calculate_risk(findings)
    reachable = fetch.error is None and fetch.status_code is not None
    application_ok = (
        (200 <= fetch.status_code < 300) if fetch.status_code is not None else None
    )

    limitations = [
        "This scan performs one GET request plus at most a small number of validated redirects.",
        "Only HTTP status, response headers, and timing are assessed. Response bodies are not analysed; a bounded read enforces the size limit.",
        "A missing security header is a configuration observation, not confirmation of an exploitable vulnerability.",
        "No authentication testing, authorization bypass, injection, rate-limit, business-logic, or destructive testing is performed.",
        "Results can vary by CDN, WAF, load balancer, edge node, and point in time.",
        "The risk score is a project-defined additive rubric, not a validated industry-standard score.",
    ]
    if settings.allow_loopback:
        limitations.append(
            "Loopback scanning is enabled for local demonstration. Never expose this mode to untrusted users."
        )
    if fetch.error is not None:
        limitations.append(
            "No HTTP response was received, so HTTP security-header checks could not be performed."
        )
    if fetch.redirect_problem is not None:
        limitations.append(
            "A redirect was not followed because it failed validation or exceeded the redirect limit."
        )
    if fetch.body_truncated:
        limitations.append(
            f"The response body was capped at {settings.max_body_bytes} bytes; body contents are not part of this assessment."
        )
    if demo:
        limitations.append(
            "This is a locally generated demonstration report. No outbound request was made."
        )
    limitations.extend(extra_limitations)

    return ScanReport(
        report_id=report_id or str(uuid.uuid4()),
        scanner_version=VERSION,
        rule_version=RULE_VERSION,
        target_url=fetch.requested_url,
        final_url=fetch.final_url,
        scanned_at=scanned_at or _utc_now(),
        reachable=reachable,
        http_status=fetch.status_code,
        http_reason=_safe_text(fetch.reason, 120) if fetch.reason else None,
        application_ok=application_ok,
        response_time_ms=round(fetch.elapsed_ms, 1) if reachable and fetch.elapsed_ms is not None else None,
        risk_score=score,
        risk_level=level,
        findings=findings,
        checks=checks,
        redirect_chain=list(fetch.chain),
        redirect_count=max(0, len(fetch.chain) - 1),
        redirect_problem=(
            RedirectProblemInfo(
                kind=fetch.redirect_problem.kind,
                location=_safe_text(fetch.redirect_problem.location, 500),
                message=fetch.redirect_problem.message,
            )
            if fetch.redirect_problem
            else None
        ),
        body_bytes_read=fetch.body_bytes,
        response_truncated=fetch.body_truncated,
        demo=demo,
        limitations=limitations,
        error=(
            ErrorInfo(code=fetch.error.code, message=fetch.error.message)
            if fetch.error
            else None
        ),
        risk_model=RISK_MODEL,
    )
