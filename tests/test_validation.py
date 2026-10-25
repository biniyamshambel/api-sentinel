from __future__ import annotations

import asyncio

import pytest

from app.errors import ScanInputError
from app.url_safety import NetworkPolicy
from tests.helpers import PUBLIC_TEST_IP, make_resolver, make_settings


def validate(url: str, *, settings=None, mapping=None):
    settings = settings or make_settings()
    policy = NetworkPolicy(settings, resolver=make_resolver(mapping))
    return asyncio.run(policy.validate_url(url))


def error_code(url: str, *, settings=None, mapping=None) -> str:
    with pytest.raises(ScanInputError) as excinfo:
        validate(url, settings=settings, mapping=mapping)
    return excinfo.value.code


def test_valid_https_url_is_canonicalised():
    target = validate("  https://API.Example.com/v1/health?x=1#fragment  ")

    assert target.url == "https://api.example.com/v1/health?x=1"
    assert target.scheme == "https"
    assert target.host == "api.example.com"
    assert target.port == 443
    assert target.addresses
    assert target.addresses[0].text == PUBLIC_TEST_IP


def test_default_http_port_is_elided_and_custom_port_preserved():
    assert validate("http://example.com:80").url == "http://example.com/"
    assert validate("http://example.com:8080/api").url == "http://example.com:8080/api"


def test_public_ipv6_target_is_preserved_with_brackets():
    target = validate("https://[2606:4700:4700::1111]/health")
    assert target.host == "2606:4700:4700::1111"
    assert target.url == "https://[2606:4700:4700::1111]/health"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/file",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "example.com",
    ],
)
def test_non_http_schemes_are_rejected(url):
    assert error_code(url) == "invalid_scheme"


def test_missing_hostname_is_rejected():
    assert error_code("http://") == "invalid_url"


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@example.com/",
        "https://user@example.com/",
    ],
)
def test_embedded_credentials_are_rejected(url):
    assert error_code(url) == "credentials_not_allowed"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:22/",
        "http://example.com:6379/",
        "http://example.com:3306/",
    ],
)
def test_restricted_ports_are_rejected(url):
    assert error_code(url) == "port_not_allowed"


@pytest.mark.parametrize("url", ["https://example.com:abc/", "https://example.com:99999/"])
def test_malformed_ports_are_rejected(url):
    assert error_code(url) == "invalid_port"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8001/",
        "http://localhost:8001/",
        "http://10.0.0.7/",
        "http://172.16.0.9/",
        "http://192.168.1.20/",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/",
        "http://[::1]:8001/",
        "http://[::ffff:127.0.0.1]/",
    ],
)
def test_loopback_private_link_local_and_reserved_targets_are_blocked(url):
    mapping = {"localhost": "127.0.0.1"}
    assert error_code(url, mapping=mapping) == "blocked_destination"


def test_public_address_is_allowed():
    target = validate("https://api.example.com/health")
    assert target.addresses[0].text == PUBLIC_TEST_IP


def test_split_horizon_answer_with_any_private_address_is_rejected():
    mapping = {"split.example.com": ["93.184.216.34", "10.0.0.7"]}
    assert error_code("https://split.example.com/", mapping=mapping) == "blocked_destination"


@pytest.mark.parametrize(
    "url",
    [
        "http://metadata.google.internal/",
        "http://printer.local/",
        "http://service.home.arpa/",
    ],
)
def test_local_and_internal_hostnames_are_rejected(url):
    assert error_code(url) == "local_hostname"


def test_loopback_is_allowed_only_with_explicit_demo_flag():
    settings = make_settings(allow_loopback=True)
    target = validate("http://127.0.0.1:8001/health", settings=settings)
    assert target.host == "127.0.0.1"


def test_private_network_remains_blocked_even_with_loopback_flag():
    settings = make_settings(allow_loopback=True)
    assert error_code("http://10.0.0.7/", settings=settings) == "blocked_destination"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com\\@evil.com/",
        "https://example.com /path",
        "http://%31%32%37.0.0.1/",
    ],
)
def test_url_parser_evasion_attempts_are_rejected(url):
    code = error_code(url)
    assert code in {"invalid_url", "invalid_host"}


def test_overlong_url_is_rejected():
    assert error_code("https://example.com/" + ("a" * 3000)) == "url_too_long"


def test_dns_failure_is_reported_safely():
    async def failing_resolver(host: str, port: int):
        raise ScanInputError("dns_failure", "The hostname could not be resolved.")

    policy = NetworkPolicy(make_settings(), resolver=failing_resolver)
    with pytest.raises(ScanInputError) as excinfo:
        asyncio.run(policy.validate_url("https://does-not-exist.example/"))
    assert excinfo.value.code == "dns_failure"


def test_custom_port_allow_list_is_enforced():
    settings = make_settings(ports=frozenset({443}))
    assert error_code("http://example.com/", settings=settings) == "port_not_allowed"
    target = validate("https://example.com/", settings=settings)
    assert target.port == 443
