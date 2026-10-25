"""URL and destination validation (SSRF defence).

Design notes
------------
* This module performs *syntactic* validation, DNS resolution and an initial
  address-policy check.  It is advisory for the request that follows.
* The authoritative check is performed by ``app.network`` at socket-connect
  time: it resolves the hostname, validates every returned address, and then
  connects to the validated IP literal.  The hostname is never re-resolved
  between validation and connection, which closes the classic DNS-rebinding
  time-of-check/time-of-use window.
* A hostname is rejected if *any* address it resolves to is not permitted.  We
  do not silently pick the "safe" answer from a split-horizon DNS response.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable, Sequence
from urllib.parse import urlsplit, urlunsplit

from .config import MAX_DNS_ANSWERS, MAX_URL_LENGTH, Settings
from .errors import ScanInputError

Resolver = Callable[[str, int], Awaitable[Sequence[tuple[int, str]]]]

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_BLOCKED_HOST_SUFFIXES = (
    ".local",
    ".internal",
    ".home.arpa",
    ".lan",
    ".intranet",
    ".corp",
)
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Networks that must never be contacted through this application.  The
# ``is_global`` check below is the default deny, but naming these explicitly
# makes the policy reviewable - and catches transition mechanisms that embed
# an IPv4 address.
_ALWAYS_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "64:ff9b::/96",  # NAT64; can embed private IPv4 destinations
        "100::/64",
        "2001::/32",  # Teredo
        "2001:db8::/32",
        "2002::/16",  # 6to4; can embed private IPv4 destinations
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)
@dataclass(frozen=True)
class ResolvedAddress:
    family: int
    ip: _IPAddress

    @property
    def text(self) -> str:
        return str(self.ip)


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[ResolvedAddress, ...]


def _unwrap_mapped(ip: _IPAddress) -> _IPAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def address_is_allowed(ip: _IPAddress, *, allow_loopback: bool) -> bool:
    """Return True only for globally routable addresses (plus explicit loopback)."""

    ip = _unwrap_mapped(ip)

    if ip.is_loopback:
        return allow_loopback

    # Explicitly deny reserved/transition ranges even where ipaddress might
    # consider an address global.
    for network in _ALWAYS_BLOCKED_NETWORKS:
        if ip.version == network.version and ip in network:
            return False

    if (
        ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    return bool(ip.is_global)


def _validate_hostname(hostname: str) -> str:
    host = hostname.strip().lower().rstrip(".")
    if not host:
        raise ScanInputError("invalid_url", "The URL must include a hostname.")
    if "%" in host:
        raise ScanInputError(
            "invalid_host",
            "IPv6 zone identifiers and percent-encoded hosts are not supported.",
        )

    # Literal IP address (IPv4 or IPv6)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if ":" in host:
        raise ScanInputError("invalid_host", "The hostname is not a valid IP address.")

    for suffix in _BLOCKED_HOST_SUFFIXES:
        if host.endswith(suffix):
            raise ScanInputError(
                "local_hostname",
                "Local and internal hostnames are not permitted scan targets.",
            )

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScanInputError("invalid_host", "The hostname is not valid.") from exc

    if len(ascii_host) > 253:
        raise ScanInputError("invalid_host", "The hostname is too long.")

    labels = ascii_host.split(".")
    if any(not _LABEL_RE.match(label) for label in labels):
        raise ScanInputError(
            "invalid_host",
            "The hostname contains unsupported characters.",
        )
    return ascii_host


def _display_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _canonical_url(scheme: str, host: str, port: int, path: str, query: str) -> str:
    default_port = 443 if scheme == "https" else 80
    netloc = _display_host(host)
    if port != default_port:
        netloc = f"{netloc}:{port}"
    return urlunsplit((scheme, netloc, path or "/", query, ""))


class NetworkPolicy:
    """Destination policy used by both URL validation and the socket layer."""

    def __init__(
        self,
        settings: Settings | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self.settings = settings or Settings.from_env()
        self._resolver = resolver

    async def _resolve_raw(self, host: str, port: int) -> Sequence[tuple[int, str]]:
        if self._resolver is not None:
            try:
                return await self._resolver(host, port)
            except ScanInputError:
                raise
            except Exception as exc:  # resolver failures must not leak internals
                raise ScanInputError(
                    "dns_failure", "The hostname could not be resolved."
                ) from exc

        try:
            infos = await asyncio.wait_for(
                asyncio.to_thread(
                    socket.getaddrinfo,
                    host,
                    port,
                    0,
                    socket.SOCK_STREAM,
                ),
                timeout=self.settings.dns_timeout_seconds,
            )
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise ScanInputError(
                "dns_timeout", "DNS resolution timed out. Check the hostname and try again."
            ) from exc
        except socket.gaierror as exc:
            raise ScanInputError(
                "dns_failure", "The hostname could not be resolved."
            ) from exc
        except OSError as exc:
            raise ScanInputError(
                "dns_failure", "The hostname could not be resolved."
            ) from exc

        answers: list[tuple[int, str]] = []
        for family, _type, _proto, _canonname, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            answers.append((family, sockaddr[0]))
        return answers

    async def resolve(self, host: str, port: int) -> tuple[ResolvedAddress, ...]:
        """Resolve and validate a destination; used by the actual connect path."""

        if port not in self.settings.allowed_ports:
            raise ScanInputError(
                "port_not_allowed",
                "That destination port is not permitted. "
                f"Allowed ports: {', '.join(str(p) for p in sorted(self.settings.allowed_ports))}.",
            )

        answers = await self._resolve_raw(host, port)
        if not answers:
            raise ScanInputError("dns_failure", "The hostname did not resolve to an address.")
        if len(answers) > MAX_DNS_ANSWERS:
            raise ScanInputError(
                "too_many_addresses",
                "The hostname resolved to too many addresses to assess safely.",
            )

        addresses: list[ResolvedAddress] = []
        seen: set[tuple[int, str]] = set()
        for family, raw_ip in answers:
            try:
                ip = ipaddress.ip_address(raw_ip)
            except ValueError as exc:
                raise ScanInputError(
                    "dns_failure", "The hostname resolved to an invalid address."
                ) from exc

            effective_ip = _unwrap_mapped(ip)
            if not address_is_allowed(
                effective_ip, allow_loopback=self.settings.allow_loopback
            ):
                raise ScanInputError(
                    "blocked_destination",
                    "The target resolves to a non-public or otherwise restricted "
                    "address. This application only scans authorized public HTTP endpoints.",
                )

            key = (family, str(ip))
            if key not in seen:
                seen.add(key)
                addresses.append(ResolvedAddress(family=family, ip=ip))

        return tuple(addresses)

    async def validate_url(self, raw_url: str) -> Target:
        if not isinstance(raw_url, str):
            raise ScanInputError("invalid_url", "The target URL must be a string.")

        value = raw_url.strip()
        if not value:
            raise ScanInputError("invalid_url", "Please enter a URL to scan.")
        if len(value) > MAX_URL_LENGTH:
            raise ScanInputError(
                "url_too_long", f"URLs are limited to {MAX_URL_LENGTH} characters."
            )
        if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            raise ScanInputError("invalid_url", "The URL must not contain whitespace or control characters.")
        if "\\" in value:
            raise ScanInputError("invalid_url", "Backslashes are not permitted in URLs.")

        try:
            parts = urlsplit(value)
        except ValueError as exc:
            raise ScanInputError("invalid_url", "The URL could not be parsed.") from exc

        scheme = parts.scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise ScanInputError(
                "invalid_scheme", "Only http:// and https:// URLs can be scanned."
            )
        if not parts.netloc:
            raise ScanInputError("invalid_url", "The URL must include a hostname.")
        if "@" in parts.netloc or parts.username is not None or parts.password is not None:
            raise ScanInputError(
                "credentials_not_allowed",
                "URLs containing embedded usernames or passwords are not permitted.",
            )

        hostname = parts.hostname
        if not hostname:
            raise ScanInputError("invalid_url", "The URL must include a hostname.")
        host = _validate_hostname(hostname)

        try:
            port = parts.port
        except ValueError as exc:
            raise ScanInputError("invalid_port", "The URL contains an invalid port.") from exc
        if port is None:
            port = 443 if scheme == "https" else 80
        if port not in self.settings.allowed_ports:
            allowed = ", ".join(str(p) for p in sorted(self.settings.allowed_ports))
            raise ScanInputError(
                "port_not_allowed",
                f"Port {port} is not permitted. Allowed ports: {allowed}.",
            )

        addresses = await self.resolve(host, port)
        canonical = _canonical_url(scheme, host, port, parts.path, parts.query)
        return Target(
            url=canonical,
            scheme=scheme,
            host=host,
            port=port,
            addresses=addresses,
        )
