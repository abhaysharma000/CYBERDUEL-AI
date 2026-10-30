"""Safe URL parsing, normalization, and canonicalization engine."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

import idna

# Sensitive query parameter names that must be redacted from query strings
SENSITIVE_QUERY_PARAMS = {
    "token",
    "access_token",
    "auth",
    "key",
    "apikey",
    "api_key",
    "password",
    "passwd",
    "secret",
    "session",
    "sessionid",
    "session_id",
    "jwt",
    "bearer",
    "code",
    "pin",
    "otp",
}

# Supported protocol schemes for web defense inspection
SUPPORTED_SCHEMES = {"http", "https"}


@dataclass(frozen=True)
class NormalizedURL:
    """Immutable structured representation of a normalized, validated URL."""

    raw_input: str
    scheme: str
    host: str
    unicode_host: str
    port: int | None
    path: str
    query: str | None
    fragment: str | None
    canonical_url: str
    domain: str
    subdomains: list[str]
    url_sha256: str
    domain_sha256: str
    has_embedded_credentials: bool
    userinfo: str | None
    is_ip_literal: bool
    is_punycode: bool


class URLNormalizationError(ValueError):
    """Raised when a URL cannot be safely normalized or validated."""

    def __init__(self, message: str, code: str = "INVALID_URL") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class URLNormalizer:
    """Robust, defensive URL normalizer complying with RFC 3986 and WHATWG standards."""

    MAX_URL_LENGTH = 4096
    MAX_HOST_LENGTH = 253

    @classmethod
    def normalize(cls, raw_url: str) -> NormalizedURL:
        """Parse and canonicalize a URL with strict security validations.

        Raises:
            URLNormalizationError: If the URL is syntactically invalid, uses an unsupported
                                   scheme, or violates length constraints.
        """
        if not isinstance(raw_url, str):
            raise URLNormalizationError("URL input must be a string.", code="INVALID_TYPE")

        cleaned = raw_url.strip()
        if not cleaned:
            raise URLNormalizationError("URL input cannot be empty.", code="EMPTY_INPUT")

        if len(cleaned) > cls.MAX_URL_LENGTH:
            raise URLNormalizationError(
                f"URL exceeds maximum allowed length of {cls.MAX_URL_LENGTH} characters.",
                code="URL_TOO_LONG",
            )

        # Disallow control characters and null bytes
        if any(ord(c) < 32 or ord(c) == 127 for c in cleaned):
            raise URLNormalizationError(
                "URL contains forbidden ASCII control characters or null bytes.",
                code="CONTROL_CHARACTERS",
            )

        # Parse with urllib.parse.urlsplit
        try:
            parts = urlsplit(cleaned)
        except Exception as e:
            raise URLNormalizationError(f"URL parsing failed: {e}", code="PARSE_ERROR") from e

        # 1. Validate Scheme
        raw_scheme = parts.scheme.lower()
        if not raw_scheme:
            raise URLNormalizationError(
                "URL scheme is missing. Only http:// and https:// URLs are supported.",
                code="MISSING_SCHEME",
            )

        if raw_scheme not in SUPPORTED_SCHEMES:
            raise URLNormalizationError(
                f"Unsupported URL scheme '{raw_scheme}'. Only http and https are permitted.",
                code="UNSUPPORTED_SCHEME",
            )

        scheme = raw_scheme

        # 2. Extract and sanitize authority (userinfo / credentials)
        userinfo: str | None = None
        has_embedded_credentials = False
        netloc = parts.netloc

        if "@" in netloc:
            has_embedded_credentials = True
            userinfo_part, host_port_part = netloc.rsplit("@", 1)
            # Redact password if present in userinfo
            if ":" in userinfo_part:
                user, _ = userinfo_part.split(":", 1)
                userinfo = f"{user}:[REDACTED]"
            else:
                userinfo = userinfo_part
            netloc = host_port_part

        if not netloc:
            raise URLNormalizationError(
                "URL authority/hostname is missing.", code="MISSING_HOSTNAME"
            )

        # 3. Extract and normalize Host and Port
        host: str
        port: int | None = None

        if netloc.startswith("["):
            # IPv6 literal format: [::1]:port
            if "]" not in netloc:
                raise URLNormalizationError(
                    "Malformed IPv6 authority bracket.", code="INVALID_IPV6"
                )
            host_bracket_end = netloc.index("]")
            host_candidate = netloc[1:host_bracket_end]
            port_part = netloc[host_bracket_end + 1 :]
            try:
                ip_obj = ipaddress.ip_address(host_candidate)
                if not isinstance(ip_obj, ipaddress.IPv6Address):
                    raise ValueError("Not an IPv6 address")
                host = f"[{ip_obj.compressed}]"
            except ValueError as e:
                raise URLNormalizationError(
                    f"Invalid IPv6 literal: {e}", code="INVALID_IPV6"
                ) from e

            if port_part:
                if not port_part.startswith(":"):
                    raise URLNormalizationError(
                        "Invalid port separator in IPv6 URL.", code="INVALID_PORT"
                    )
                port = cls._validate_port(port_part[1:])
        elif ":" in netloc:
            host_candidate, port_candidate = netloc.rsplit(":", 1)
            host = host_candidate
            port = cls._validate_port(port_candidate)
        else:
            host = netloc

        # Strip trailing dot from hostname (e.g., google.com. -> google.com)
        host = host.rstrip(".")
        if not host:
            raise URLNormalizationError("Hostname cannot be empty.", code="EMPTY_HOSTNAME")

        if len(host) > cls.MAX_HOST_LENGTH:
            raise URLNormalizationError(
                f"Hostname exceeds maximum length of {cls.MAX_HOST_LENGTH} characters.",
                code="HOST_TOO_LONG",
            )

        # 4. Check for IP literal (IPv4)
        is_ip_literal = False
        if not host.startswith("["):
            try:
                ip_v4 = ipaddress.IPv4Address(host)
                host = str(ip_v4)
                is_ip_literal = True
            except ValueError:
                # Not a direct dotted IPv4; check for integer/octal obfuscated IP
                if host.isdigit():
                    try:
                        int_val = int(host)
                        if 0 <= int_val <= 0xFFFFFFFF:
                            host = str(ipaddress.IPv4Address(int_val))
                            is_ip_literal = True
                    except ValueError:
                        pass
        else:
            is_ip_literal = True

        # 5. Internationalized Domain Name (IDN) & Punycode handling
        is_punycode = False
        unicode_host = host

        if not is_ip_literal:
            # Check for non-ASCII characters or existing punycode
            try:
                if host.lower().startswith("xn--") or ".xn--" in host.lower():
                    is_punycode = True
                    unicode_host = idna.decode(host.encode("ascii"))
                    host = host.lower()
                else:
                    # Convert Unicode to canonical ASCII Punycode
                    ascii_host = idna.encode(host, uts46=True).decode("ascii").lower()
                    if ascii_host != host.lower() or "xn--" in ascii_host:
                        is_punycode = True
                    unicode_host = idna.decode(ascii_host.encode("ascii"))
                    host = ascii_host
            except idna.IDNAError as e:
                raise URLNormalizationError(
                    f"Internationalized domain name error: {e}", code="INVALID_IDN"
                ) from e

        # Validate host characters
        if not is_ip_literal and not re.match(r"^[a-z0-9\-\.]+$", host):
            raise URLNormalizationError(
                f"Hostname contains invalid characters: '{host}'", code="INVALID_HOST_CHARS"
            )

        # 6. Default Port Normalization
        if scheme == "http" and port == 80 or scheme == "https" and port == 443:
            port = None

        # 7. Domain and Subdomain Extraction
        domain, subdomains = cls._extract_domain_and_subdomains(host, is_ip_literal)

        # 8. Path Normalization (RFC 3986 section 5.2.4: remove dot segments)
        raw_path = parts.path or "/"
        normalized_path = cls._normalize_path(raw_path)

        # 9. Query Normalization & Sensitive Token Redaction
        normalized_query = cls._normalize_query(parts.query) if parts.query else None

        # 10. Fragment (preserved for analysis, stripped from external lookup digests)
        fragment = parts.fragment if parts.fragment else None

        # 11. Canonical URL Construction
        port_str = f":{port}" if port is not None else ""
        query_str = f"?{normalized_query}" if normalized_query is not None else ""
        canonical_url = f"{scheme}://{host}{port_str}{normalized_path}{query_str}"

        # 12. Cryptographic Digests
        url_sha256 = hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()
        domain_sha256 = hashlib.sha256(domain.encode("utf-8")).hexdigest()

        return NormalizedURL(
            raw_input=cleaned,
            scheme=scheme,
            host=host,
            unicode_host=unicode_host,
            port=port,
            path=normalized_path,
            query=normalized_query,
            fragment=fragment,
            canonical_url=canonical_url,
            domain=domain,
            subdomains=subdomains,
            url_sha256=url_sha256,
            domain_sha256=domain_sha256,
            has_embedded_credentials=has_embedded_credentials,
            userinfo=userinfo,
            is_ip_literal=is_ip_literal,
            is_punycode=is_punycode,
        )

    @classmethod
    def _validate_port(cls, port_str: str) -> int:
        if not port_str.isdigit():
            raise URLNormalizationError(f"Port must be numeric: '{port_str}'", code="INVALID_PORT")
        port_val = int(port_str)
        if not (1 <= port_val <= 65535):
            raise URLNormalizationError(
                f"Port out of range [1-65535]: {port_val}", code="PORT_OUT_OF_RANGE"
            )
        return port_val

    @classmethod
    def _normalize_path(cls, path: str) -> str:
        """Resolve dot segments, double slashes, and normalize percent-encodings."""
        if not path:
            return "/"

        # Unquote once to detect double-encoding, then re-quote safely
        unquoted = unquote(path)
        # Check for null bytes or control characters in path
        if "\0" in unquoted:
            raise URLNormalizationError("Null byte in path component.", code="NULL_BYTE_PATH")

        # Resolve dot segments
        segments = unquoted.split("/")
        resolved: list[str] = []
        for segment in segments:
            if segment == "." or segment == "":
                continue
            if segment == "..":
                if resolved:
                    resolved.pop()
            else:
                resolved.append(segment)

        reconstructed = "/" + "/".join(resolved)
        if path.endswith("/") and not reconstructed.endswith("/"):
            reconstructed += "/"

        # Re-quote path segments safely
        return quote(reconstructed, safe="/:@&+$,;=-_.!~*'()")

    @classmethod
    def _normalize_query(cls, raw_query: str) -> str:
        """Sort query parameters and redact sensitive tokens."""
        try:
            pairs = parse_qsl(raw_query, keep_blank_values=True)
        except Exception:
            return raw_query

        sanitized_pairs: list[tuple[str, str]] = []
        for k, v in pairs:
            if k.lower() in SENSITIVE_QUERY_PARAMS:
                sanitized_pairs.append((k, "[REDACTED]"))
            else:
                sanitized_pairs.append((k, v))

        # Sort parameters for canonical determinism
        sanitized_pairs.sort(key=lambda item: (item[0], item[1]))
        return urlencode(sanitized_pairs)

    @classmethod
    def _extract_domain_and_subdomains(cls, host: str, is_ip: bool) -> tuple[str, list[str]]:
        """Extract registrable domain and constituent subdomain labels."""
        if is_ip or "[" in host:
            return host, []

        labels = host.split(".")
        if len(labels) <= 2:
            return host, []

        # Common multi-part ccTLDs: co.uk, com.au, co.jp, etc.
        cc_two_level = {"co.uk", "gov.uk", "ac.uk", "org.uk", "com.au", "net.au", "co.jp"}
        last_two = f"{labels[-2]}.{labels[-1]}"

        if last_two in cc_two_level and len(labels) >= 3:
            domain = f"{labels[-3]}.{last_two}"
            subdomains = labels[:-3]
        else:
            domain = f"{labels[-2]}.{labels[-1]}"
            subdomains = labels[:-2]

        return domain, subdomains
