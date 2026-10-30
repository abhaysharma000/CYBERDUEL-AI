"""Deterministic numerical and categorical feature extraction for URL evaluation."""

from __future__ import annotations

import math
from typing import Any

from cyberduel_threat_intel.heuristics import (
    HIGH_VALUE_BRANDS,
    PHISHING_KEYWORDS,
    TRUSTED_TOP_DOMAINS,
)
from cyberduel_threat_intel.normalizer import NormalizedURL


class URLFeatureExtractor:
    """Extracts reproducible statistical and structural features from a NormalizedURL."""

    @classmethod
    def extract_features(cls, url: NormalizedURL) -> dict[str, Any]:
        """Produce deterministic feature dictionary suitable for ML models and audit logs."""
        canonical = url.canonical_url
        host = url.host
        path = url.path
        query = url.query or ""

        # Entropy calculations
        host_entropy = cls._entropy(host)
        path_entropy = cls._entropy(path)

        # Keyword matching count
        combined_text = f"{host} {path} {query}".lower()
        phish_keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in combined_text)

        # Brand presence flag
        brand_detected = any(brand in combined_text for brand in HIGH_VALUE_BRANDS)

        return {
            "url_length": len(canonical),
            "host_length": len(host),
            "path_length": len(path),
            "query_length": len(query),
            "subdomain_count": len(url.subdomains),
            "dot_count_in_host": host.count("."),
            "hyphen_count_in_host": host.count("-"),
            "digit_count_in_host": sum(1 for c in host if c.isdigit()),
            "special_char_count_in_path": sum(1 for c in path if not c.isalnum() and c != "/"),
            "is_ip_literal": 1 if url.is_ip_literal else 0,
            "is_punycode": 1 if url.is_punycode else 0,
            "has_embedded_credentials": 1 if url.has_embedded_credentials else 0,
            "has_non_standard_port": 1 if url.port is not None and url.port not in {80, 443} else 0,
            "host_entropy": round(host_entropy, 4),
            "path_entropy": round(path_entropy, 4),
            "phish_keyword_count": phish_keyword_count,
            "brand_token_detected": 1 if brand_detected else 0,
            "has_double_encoding": 1 if "%25" in url.raw_input.lower() else 0,
            "is_whitelisted": 1 if url.domain in TRUSTED_TOP_DOMAINS else 0,
        }

    @classmethod
    def _entropy(cls, text: str) -> float:
        if not text:
            return 0.0
        length = len(text)
        freqs = (text.count(c) / length for c in set(text))
        return -sum(p * math.log2(p) for p in freqs if p > 0)
