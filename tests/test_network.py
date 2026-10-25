from __future__ import annotations

import asyncio
import socket

import pytest

from app.errors import ScanInputError
from app.network import SafeFetcher
from app.scanner import build_report
from app.url_safety import NetworkPolicy
from tests.helpers import PUBLIC_TEST_IP, make_resolver, make_settings


def fetch(settings, url: str):
    return asyncio.run(SafeFetcher(settings=settings).fetch(url))


def test_real_local_fetch_and_assessment(loopback_settings, local_server):
    base = f"http://127.0.0.1:{local_server}"
    result = fetch(loopback_settings, f"{base}/ok")

    assert result.error is None
    assert result.status_code == 200
    assert result.final_url == f"{base}/ok"
    assert result.headers["x-content-type-options"] == "nosniff"
    assert result.elapsed_ms is not None

    report = build_report(result, loopback_settings)
    assert report.reachable is True
    assert report.application_ok is True
    assert {finding.id for finding in report.findings} == {"transport.plaintext_http"}
    assert report.risk_score == 25


def test_loopback_is_blocked_without_demo_flag(local_server):
    settings = make_settings(allow_loopback=False, ports=frozenset({local_server}))
    with pytest.raises(ScanInputError) as excinfo:
        fetch(settings, f"http://127.0.0.1:{local_server}/ok")
    assert excinfo.value.code == "blocked_destination"


def test_public_redirect_is_followed_and_recorded(loopback_settings, local_server):
    base = f"http://127.0.0.1:{local_server}"
    result = fetch(loopback_settings, f"{base}/redirect")

    assert result.error is None
    assert result.status_code == 200
    assert result.final_url == f"{base}/ok"
    assert result.chain == (f"{base}/redirect", f"{base}/ok")

    report = build_report(result, loopback_settings)
    assert report.redirect_count == 1
    assert report.redirect_problem is None


def test_redirect_to_link_local_metadata_is_blocked(loopback_settings, local_server):
    base = f"http://127.0.0.1:{local_server}"
    result = fetch(loopback_settings, f"{base}/redirect-private")

    assert result.error is None
    assert result.status_code == 302
    assert result.redirect_problem is not None
    assert result.redirect_problem.kind == "blocked"
    assert result.chain == (f"{base}/redirect-private",)

    report = build_report(result, loopback_settings)
    assert report.reachable is True
    assert report.application_ok is False
    assert any(finding.id == "redirect.blocked" for finding in report.findings)


def test_response_body_is_bounded(loopback_settings, local_server):
    base = f"http://127.0.0.1:{local_server}"
    result = fetch(loopback_settings, f"{base}/large")

    assert result.error is None
    assert result.body_truncated is True
    assert result.body_bytes <= loopback_settings.max_body_bytes


def test_slow_target_times_out(local_server):
    settings = make_settings(
        allow_loopback=True,
        ports=frozenset({local_server}),
        timeout=0.25,
    )
    result = fetch(settings, f"http://127.0.0.1:{local_server}/slow")

    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.status_code is None


def test_connection_refused_is_handled():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    settings = make_settings(
        allow_loopback=True,
        ports=frozenset({closed_port}),
        timeout=1.0,
    )
    result = fetch(settings, f"http://127.0.0.1:{closed_port}/")

    assert result.error is not None
    assert result.error.code == "connection_failed"


def test_dns_rebinding_to_private_address_is_blocked_at_connect_time():
    calls = 0

    async def alternating_resolver(host: str, port: int):
        nonlocal calls
        calls += 1
        # First answer passes URL validation; second answer would reach loopback.
        address = PUBLIC_TEST_IP if calls == 1 else "127.0.0.1"
        return [(socket.AF_INET, address)]

    settings = make_settings(allow_loopback=False)
    policy = NetworkPolicy(settings, resolver=alternating_resolver)
    fetcher = SafeFetcher(settings=settings, policy=policy)
    result = asyncio.run(fetcher.fetch("http://rebind.example/"))

    assert calls >= 2
    assert result.error is not None
    assert result.error.code == "blocked_destination"
    assert result.status_code is None


def test_split_horizon_resolution_is_rejected_before_connection():
    settings = make_settings(allow_loopback=False)
    policy = NetworkPolicy(
        settings,
        resolver=make_resolver({"mixed.example": [PUBLIC_TEST_IP, "10.0.0.8"]}),
    )
    fetcher = SafeFetcher(settings=settings, policy=policy)
    with pytest.raises(ScanInputError) as excinfo:
        asyncio.run(fetcher.fetch("https://mixed.example/"))
    assert excinfo.value.code == "blocked_destination"
