from __future__ import annotations

import ipaddress
import socket
from typing import Callable

import httpx

from app.config import DEFAULT_ALLOWED_PORTS, Settings
from app.network import SafeFetcher
from app.url_safety import NetworkPolicy

PUBLIC_TEST_IP = "93.184.216.34"


def make_settings(
    *,
    allow_loopback: bool = False,
    ports: frozenset[int] | None = None,
    timeout: float = 2.0,
    max_redirects: int = 2,
    max_body_bytes: int = 1024,
) -> Settings:
    return Settings(
        allow_loopback=allow_loopback,
        allowed_ports=ports or DEFAULT_ALLOWED_PORTS,
        timeout_seconds=timeout,
        dns_timeout_seconds=1.0,
        max_redirects=max_redirects,
        max_body_bytes=max_body_bytes,
    )


def make_resolver(
    mapping: dict[str, str | list[str]] | None = None,
    default: str = PUBLIC_TEST_IP,
) -> Callable[[str, int], object]:
    """Deterministic resolver for tests; literal IPs resolve to themselves."""

    mapping = mapping or {}

    async def resolver(host: str, port: int):
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            value = mapping.get(host, default)
            values = value if isinstance(value, (list, tuple)) else [value]
            addresses = [ipaddress.ip_address(str(item)) for item in values]
        return [
            (socket.AF_INET6 if address.version == 6 else socket.AF_INET, str(address))
            for address in addresses
        ]

    return resolver


def mock_fetcher(
    settings: Settings,
    handler: Callable[[httpx.Request], httpx.Response],
    mapping: dict[str, str | list[str]] | None = None,
) -> SafeFetcher:
    policy = NetworkPolicy(settings, resolver=make_resolver(mapping))
    return SafeFetcher(
        settings=settings,
        policy=policy,
        transport=httpx.MockTransport(handler),
    )
