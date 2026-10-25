"""Runtime configuration for API Sentinel.

The defaults are deliberately conservative.  In particular, loopback targets are
blocked unless the operator explicitly opts in for a local demonstration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

APP_NAME = "API Sentinel"
VERSION = "1.0.0"
RULE_VERSION = "2026.1"

# Ports that are useful for public HTTP APIs and local development servers.
# This is an allow-list, not a list of "interesting" ports to probe.
DEFAULT_ALLOWED_PORTS: frozenset[int] = frozenset({80, 443, 8000, 8001, 8080, 8443})

DEFAULT_TIMEOUT_SECONDS = 8.0
DEFAULT_DNS_TIMEOUT_SECONDS = 4.0
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_MAX_BODY_BYTES = 64 * 1024
MAX_URL_LENGTH = 2048
MAX_DNS_ANSWERS = 16


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_ports() -> frozenset[int]:
    raw = os.getenv("API_SENTINEL_ALLOWED_PORTS", "").strip()
    if not raw:
        return DEFAULT_ALLOWED_PORTS
    ports: set[int] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return frozenset(ports) if ports else DEFAULT_ALLOWED_PORTS


@dataclass(frozen=True)
class Settings:
    """Immutable scan policy shared by validation and the network backend."""

    allow_loopback: bool = False
    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    dns_timeout_seconds: float = DEFAULT_DNS_TIMEOUT_SECONDS
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            allow_loopback=_env_flag("API_SENTINEL_ALLOW_LOOPBACK"),
            allowed_ports=_env_ports(),
            timeout_seconds=float(
                os.getenv("API_SENTINEL_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
            ),
            dns_timeout_seconds=float(
                os.getenv("API_SENTINEL_DNS_TIMEOUT_SECONDS", DEFAULT_DNS_TIMEOUT_SECONDS)
            ),
            max_redirects=int(
                os.getenv("API_SENTINEL_MAX_REDIRECTS", DEFAULT_MAX_REDIRECTS)
            ),
            max_body_bytes=int(
                os.getenv("API_SENTINEL_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)
            ),
        )

    @property
    def loopback_mode(self) -> str:
        return "enabled (local demo only)" if self.allow_loopback else "disabled"
