"""Outbound HTTP client with destination validation at connect time.

The client deliberately does not use ``follow_redirects=True``.  Redirects are
followed manually so that every new destination passes through the URL policy
again.  The underlying httpcore network backend independently validates the
address it is about to connect to and pins the connection to that IP literal.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urljoin

import httpcore
import httpx

from .config import APP_NAME, VERSION, Settings
from .errors import SSRFBlockedError, ScanInputError
from .url_safety import NetworkPolicy, address_is_allowed

logger = logging.getLogger(__name__)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_USER_AGENT = f"{APP_NAME}/{VERSION} (authorized configuration check)"


@dataclass(frozen=True)
class RedirectProblem:
    kind: str  # blocked | too_many | invalid
    location: str
    message: str


@dataclass(frozen=True)
class FetchFailureInfo:
    code: str
    message: str


@dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str | None
    status_code: int | None
    reason: str | None
    headers: dict[str, str]
    elapsed_ms: float | None
    chain: tuple[str, ...]
    body_bytes: int = 0
    body_truncated: bool = False
    redirect_problem: RedirectProblem | None = None
    error: FetchFailureInfo | None = None


class _GuardedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Validate the resolved destination, then connect to that exact IP."""

    def __init__(self, policy: NetworkPolicy) -> None:
        self._policy = policy
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: list[tuple[int, int, bytes | None]] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        hostname = host.decode("ascii") if isinstance(host, bytes) else host

        if port not in self._policy.settings.allowed_ports:
            raise SSRFBlockedError("Destination port is not permitted.")

        try:
            addresses = await self._policy.resolve(hostname, port)
        except ScanInputError as exc:
            raise SSRFBlockedError(exc.message) from exc

        last_error: Exception | None = None
        for address in addresses:
            # Validate again immediately before connecting.  This is the actual
            # address used for the TCP connection, not a separately-resolved one.
            if not address_is_allowed(
                address.ip, allow_loopback=self._policy.settings.allow_loopback
            ):
                raise SSRFBlockedError("Destination address is not permitted.")
            try:
                return await self._backend.connect_tcp(
                    str(address.ip),
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:  # try the next validated address
                last_error = exc

        if last_error is not None:
            raise last_error
        raise SSRFBlockedError("No permitted destination address was available.")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: list[tuple[int, int, bytes | None]] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise SSRFBlockedError("Unix sockets are disabled for scan targets.")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class GuardedAsyncTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose connection pool uses the guarded backend."""

    def __init__(self, policy: NetworkPolicy) -> None:
        super().__init__(
            verify=True,
            trust_env=False,
            http1=True,
            http2=False,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=0),
            retries=0,
        )
        # Replace the pool created by the parent with one that uses our network
        # backend.  TLS still uses the original hostname for SNI and certificate
        # verification; only the TCP destination is pinned.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=True, trust_env=False),
            max_connections=4,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_GuardedNetworkBackend(policy),
        )


def _walk_exception_chain(exc: BaseException) -> list[BaseException]:
    seen: set[int] = set()
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _contains_ssl_error(exc: BaseException) -> bool:
    return any(isinstance(item, ssl.SSLError) for item in _walk_exception_chain(exc))


def _failure_from_exception(exc: BaseException, timeout: float) -> FetchFailureInfo:
    chain = _walk_exception_chain(exc)
    if isinstance(exc, SSRFBlockedError) or any(
        isinstance(item, SSRFBlockedError) for item in chain
    ):
        return FetchFailureInfo(
            "blocked_destination",
            "The connection was blocked because the destination is not permitted.",
        )
    if isinstance(exc, ScanInputError):
        return FetchFailureInfo(exc.code, exc.message)
    if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
        return FetchFailureInfo(
            "timeout", f"The target did not respond within {timeout:g} seconds."
        )
    if isinstance(exc, httpx.ConnectError):
        if _contains_ssl_error(exc):
            return FetchFailureInfo(
                "tls_error",
                "The TLS connection could not be established or the certificate "
                "could not be verified.",
            )
        return FetchFailureInfo(
            "connection_failed", "The connection to the target could not be established."
        )
    if isinstance(exc, httpx.UnsupportedProtocol):
        return FetchFailureInfo("unsupported_protocol", "The target protocol is not supported.")
    if isinstance(exc, httpx.HTTPError):
        logger.info("HTTP client error during scan: %s", type(exc).__name__)
        return FetchFailureInfo(
            "request_failed", "The request failed before a complete response was received."
        )
    logger.exception("Unexpected scan error", exc_info=exc)
    return FetchFailureInfo(
        "internal_error", "The scan could not be completed due to an internal error."
    )


def _combine_headers(headers: httpx.Headers) -> dict[str, str]:
    combined: dict[str, str] = {}
    for key, value in headers.multi_items():
        key = key.lower()
        combined[key] = f"{combined[key]}, {value}" if key in combined else value
    return combined


@dataclass
class SafeFetcher:
    """Perform one bounded, redirect-aware HTTP GET for a scan."""

    settings: Settings | None = None
    policy: NetworkPolicy | None = None
    transport: httpx.AsyncBaseTransport | None = None

    def __post_init__(self) -> None:
        if self.settings is None:
            self.settings = Settings.from_env()
        if self.policy is None:
            self.policy = NetworkPolicy(self.settings)

    async def fetch(self, raw_url: str) -> FetchResult:
        # Raises ScanInputError for invalid or disallowed initial targets.
        target = await self.policy.validate_url(raw_url)
        started = time.perf_counter()
        timeout = self.settings.timeout_seconds
        deadline = started + timeout
        chain: list[str] = [target.url]

        # A new transport and client are created per scan.  A borrowed transport
        # is intentionally closed with the client; SafeFetcher is single-use.
        transport = self.transport or GuardedAsyncTransport(self.policy)
        client = httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout),
            trust_env=False,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "application/json, text/plain, */*",
            },
        )

        try:
            current = target
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    failure = _failure_from_exception(TimeoutError(), timeout)
                    return FetchResult(
                        requested_url=target.url,
                        final_url=None,
                        status_code=None,
                        reason=None,
                        headers={},
                        elapsed_ms=(time.perf_counter() - started) * 1000,
                        chain=tuple(chain),
                        error=failure,
                    )

                try:
                    # Total wall-clock budget for the whole scan, including
                    # redirects and the bounded body read.
                    async with asyncio.timeout(remaining):
                        response = await client.send(
                            client.build_request("GET", current.url), stream=True
                        )
                        elapsed_ms = (time.perf_counter() - started) * 1000
                        headers = _combine_headers(response.headers)
                        status = response.status_code
                        reason = response.reason_phrase
                        body_bytes, truncated = await _consume_bounded(
                            response, self.settings.max_body_bytes
                        )
                except Exception as exc:
                    failure = _failure_from_exception(exc, timeout)
                    return FetchResult(
                        requested_url=target.url,
                        final_url=None,
                        status_code=None,
                        reason=None,
                        headers={},
                        elapsed_ms=(time.perf_counter() - started) * 1000,
                        chain=tuple(chain),
                        error=failure,
                    )

                location = headers.get("location")

                if status in _REDIRECT_STATUSES and location:
                    if len(chain) - 1 >= self.settings.max_redirects:
                        return FetchResult(
                            requested_url=target.url,
                            final_url=current.url,
                            status_code=status,
                            reason=reason,
                            headers=headers,
                            elapsed_ms=elapsed_ms,
                            chain=tuple(chain),
                            body_bytes=body_bytes,
                            body_truncated=truncated,
                            redirect_problem=RedirectProblem(
                                "too_many",
                                location[:500],
                                f"The redirect limit ({self.settings.max_redirects}) was reached.",
                            ),
                        )

                    next_url = urljoin(current.url, location)
                    try:
                        next_target = await self.policy.validate_url(next_url)
                    except ScanInputError as exc:
                        return FetchResult(
                            requested_url=target.url,
                            final_url=current.url,
                            status_code=status,
                            reason=reason,
                            headers=headers,
                            elapsed_ms=elapsed_ms,
                            chain=tuple(chain),
                            body_bytes=body_bytes,
                            body_truncated=truncated,
                            redirect_problem=RedirectProblem(
                                "blocked", next_url[:500], exc.message
                            ),
                        )

                    current = next_target
                    chain.append(current.url)
                    continue

                return FetchResult(
                    requested_url=target.url,
                    final_url=current.url,
                    status_code=status,
                    reason=reason,
                    headers=headers,
                    elapsed_ms=elapsed_ms,
                    chain=tuple(chain),
                    body_bytes=body_bytes,
                    body_truncated=truncated,
                )
        finally:
            await client.aclose()


async def _consume_bounded(response: httpx.Response, limit: int) -> tuple[int, bool]:
    """Read at most ``limit`` bytes, then close the stream."""

    received = 0
    truncated = False
    try:
        async for chunk in response.aiter_bytes():
            remaining = limit - received
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                received += remaining
                truncated = True
                break
            received += len(chunk)
            if received >= limit:
                truncated = True
                break
    except httpx.HTTPError:
        # Headers are already available; a body-read failure does not invalidate
        # the header assessment.  The stream is closed below.
        truncated = True
    finally:
        await response.aclose()
    return received, truncated
