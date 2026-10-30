"""Tests for URL parsing, canonical normalization, and structural validation."""

import pytest
from cyberduel_threat_intel.normalizer import (
    URLNormalizationError,
    URLNormalizer,
)
from cyberduel_threat_intel.validator import URLValidator


def test_standard_http_https_normalization() -> None:
    # Scheme lowercase, default port stripping, trailing slash addition
    n1 = URLNormalizer.normalize("HTTP://Example.COM:80/path/to/page")
    assert n1.scheme == "http"
    assert n1.host == "example.com"
    assert n1.port is None
    assert n1.canonical_url == "http://example.com/path/to/page"

    n2 = URLNormalizer.normalize("HTTPS://EXAMPLE.ORG:443/")
    assert n2.scheme == "https"
    assert n2.host == "example.org"
    assert n2.port is None
    assert n2.canonical_url == "https://example.org/"


def test_custom_ports_preserved() -> None:
    n = URLNormalizer.normalize("https://example.com:8443/api")
    assert n.port == 8443
    assert n.canonical_url == "https://example.com:8443/api"


def test_trailing_dot_stripped() -> None:
    n = URLNormalizer.normalize("https://google.com./search")
    assert n.host == "google.com"
    assert n.canonical_url == "https://google.com/search"


def test_unsupported_schemes_rejected() -> None:
    unsupported = [
        "javascript:alert(1)",
        "data:text/html,<h1>test</h1>",
        "ftp://files.example.com",
        "file:///etc/passwd",
        "gopher://gopher.example.com",
    ]
    for raw in unsupported:
        with pytest.raises(URLNormalizationError) as exc_info:
            URLNormalizer.normalize(raw)
        assert exc_info.value.code in {"UNSUPPORTED_SCHEME", "MISSING_SCHEME"}


def test_idn_and_punycode_handling() -> None:
    # Cyrillic IDN: münchen.de
    n = URLNormalizer.normalize("https://münchen.de/")
    assert n.is_punycode is True
    assert n.host == "xn--mnchen-3ya.de"
    assert n.unicode_host == "münchen.de"

    # Direct punycode input (Cyrillic 'a' homoglyph)
    n_puny = URLNormalizer.normalize("https://xn--pypal-4ve.com/login")
    assert n_puny.is_punycode is True
    assert "\u0430" in n_puny.unicode_host
    assert n_puny.host == "xn--pypal-4ve.com"


def test_ipv4_and_ipv6_literal_normalization() -> None:
    # IPv4
    n_ip4 = URLNormalizer.normalize("http://192.168.1.1:8080/admin")
    assert n_ip4.is_ip_literal is True
    assert n_ip4.host == "192.168.1.1"
    assert n_ip4.port == 8080

    # IPv6
    n_ip6 = URLNormalizer.normalize("http://[2001:db8::1]:8080/test")
    assert n_ip6.is_ip_literal is True
    assert n_ip6.host == "[2001:db8::1]"
    assert n_ip6.port == 8080


def test_credentials_extracted_and_stripped_from_canonical_url() -> None:
    # Destination is evil.com, username is paypal.com
    raw = "https://paypal.com:secretpassword@evil.com/login"
    n = URLNormalizer.normalize(raw)
    assert n.has_embedded_credentials is True
    assert n.host == "evil.com"
    # Canonical destination MUST NOT include the misleading userinfo
    assert n.canonical_url == "https://evil.com/login"
    # Credentials are saved in userinfo with password redacted
    assert n.userinfo == "paypal.com:[REDACTED]"


def test_query_parameter_sorting_and_token_redaction() -> None:
    raw = (
        "https://example.com/checkout?session_id=secret123&item=book&token=jwt_xyz_999&category=all"
    )
    n = URLNormalizer.normalize(raw)
    assert n.query is not None
    assert "token=%5BREDACTED%5D" in n.query or "token=[REDACTED]" in n.canonical_url
    assert "session_id=%5BREDACTED%5D" in n.query or "session_id=[REDACTED]" in n.canonical_url
    assert "item=book" in n.canonical_url


def test_path_dot_segments_resolved() -> None:
    raw = "https://example.com/a/b/../c/./d"
    n = URLNormalizer.normalize(raw)
    assert n.path == "/a/c/d"


def test_malformed_and_boundary_inputs() -> None:
    # Null byte in URL
    with pytest.raises(URLNormalizationError):
        URLNormalizer.normalize("https://example.com/test\0evil")

    # Empty string
    with pytest.raises(URLNormalizationError):
        URLNormalizer.normalize("   ")

    # Non-string input
    with pytest.raises(URLNormalizationError):
        URLNormalizer.normalize(12345)  # type: ignore[arg-type]

    # Port out of bounds
    with pytest.raises(URLNormalizationError):
        URLNormalizer.normalize("https://example.com:999999/path")

    # Missing hostname
    with pytest.raises(URLNormalizationError):
        URLNormalizer.normalize("https:///path")


def test_validator_returns_structured_result() -> None:
    res_valid = URLValidator.validate("https://google.com/search?q=test")
    assert res_valid.is_valid is True
    assert res_valid.normalized is not None

    res_invalid = URLValidator.validate("javascript:void(0)")
    assert res_invalid.is_valid is False
    assert res_invalid.error_code == "UNSUPPORTED_SCHEME"
    assert res_invalid.error_message is not None
