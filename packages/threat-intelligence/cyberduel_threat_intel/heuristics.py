"""Transparent, configurable defensive heuristic analyzer for URLs."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from cyberduel_contracts.analysis import EvidenceItem
from cyberduel_contracts.enums import ThreatSeverity

from cyberduel_threat_intel.normalizer import NormalizedURL

# High-value brands frequently targeted by deceptive mimicry campaigns
HIGH_VALUE_BRANDS = {
    "paypal",
    "microsoft",
    "apple",
    "google",
    "netflix",
    "amazon",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "binance",
    "coinbase",
    "dropbox",
    "facebook",
    "instagram",
    "linkedin",
    "adobe",
    "docusign",
}

# Verified official domains for high-value brands (Never flag as brand impersonation)
OFFICIAL_BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "azure.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "netflix": {"netflix.com"},
    "amazon": {"amazon.com", "aws.amazon.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "dropbox": {"dropbox.com"},
    "facebook": {"facebook.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com"},
}

# Known-good top domains for false-positive mitigation whitelist
TRUSTED_TOP_DOMAINS = {
    "google.com",
    "apple.com",
    "microsoft.com",
    "amazon.com",
    "github.com",
    "wikipedia.org",
    "cloudflare.com",
    "mozilla.org",
    "python.org",
    "w3.org",
    "eff.org",
    "nist.gov",
    "stackoverflow.com",
}

# TLDs historically associated with high ratios of transient malicious abuse
SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "buzz",
    "icu",
    "rest",
    "work",
}

# Action keywords common in credential harvesting lures
PHISHING_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account-update",
    "security-check",
    "confirm-identity",
    "wallet-connect",
    "billing-update",
    "password-reset",
    "secure-banking",
}


@dataclass
class HeuristicRule:
    """Specification of a deterministic defensive heuristic check."""

    rule_id: str
    version: str
    name: str
    description: str
    category: str
    severity: ThreatSeverity
    weight: float
    enabled: bool = True


class URLHeuristicAnalyzer:
    """Evaluates normalized URLs against a registry of explainable heuristic rules."""

    def __init__(self, rule_overrides: dict[str, dict[str, Any]] | None = None) -> None:
        self.rules: dict[str, HeuristicRule] = self._init_default_rules()
        if rule_overrides:
            self._apply_overrides(rule_overrides)

    def _init_default_rules(self) -> dict[str, HeuristicRule]:
        return {
            "HR-HOMOGLYPH-01": HeuristicRule(
                rule_id="HR-HOMOGLYPH-01",
                version="1.0.0",
                name="IDN Punycode Homoglyph Indicator",
                description="Detects Punycode or internationalized character sets in hostnames mimicking targets",
                category="homograph",
                severity=ThreatSeverity.HIGH,
                weight=0.65,
                enabled=True,
            ),
            "HR-CREDENTIAL-SPOOF-02": HeuristicRule(
                rule_id="HR-CREDENTIAL-SPOOF-02",
                version="1.0.0",
                name="Authority Credential Destination Spoofing",
                description="Detects embedded credentials before '@' in the authority that disguise the real host",
                category="credentials",
                severity=ThreatSeverity.CRITICAL,
                weight=0.85,
                enabled=True,
            ),
            "HR-IP-HOST-03": HeuristicRule(
                rule_id="HR-IP-HOST-03",
                version="1.0.0",
                name="Direct IP Address Host",
                description="Detects bare IPv4 or IPv6 literals used as destination hosts in web URLs",
                category="network",
                severity=ThreatSeverity.MEDIUM,
                weight=0.40,
                enabled=True,
            ),
            "HR-SUSPICIOUS-PORT-04": HeuristicRule(
                rule_id="HR-SUSPICIOUS-PORT-04",
                version="1.0.0",
                name="Non-Standard Port Execution",
                description="Detects unusual or high-range TCP ports outside standard HTTP/HTTPS channels",
                category="network",
                severity=ThreatSeverity.MEDIUM,
                weight=0.35,
                enabled=True,
            ),
            "HR-EXCESSIVE-SUBDOMAINS-05": HeuristicRule(
                rule_id="HR-EXCESSIVE-SUBDOMAINS-05",
                version="1.0.0",
                name="Excessive Subdomain Depth",
                description="Detects deep subdomain nesting used to bury attacker registrable domains",
                category="structure",
                severity=ThreatSeverity.LOW,
                weight=0.25,
                enabled=True,
            ),
            "HR-BRAND-IMPERSONATION-06": HeuristicRule(
                rule_id="HR-BRAND-IMPERSONATION-06",
                version="1.0.0",
                name="High-Value Brand Lexical Mimicry",
                description="Detects high-value brand names in subdomains or path on unauthorized foreign domains",
                category="impersonation",
                severity=ThreatSeverity.HIGH,
                weight=0.70,
                enabled=True,
            ),
            "HR-PHISH-KEYWORDS-07": HeuristicRule(
                rule_id="HR-PHISH-KEYWORDS-07",
                version="1.0.0",
                name="Credential Harvesting Action Keywords",
                description="Detects combinations of sensitive account-verification keywords in path and subdomains",
                category="lexical",
                severity=ThreatSeverity.MEDIUM,
                weight=0.30,
                enabled=True,
            ),
            "HR-DOUBLE-ENCODING-08": HeuristicRule(
                rule_id="HR-DOUBLE-ENCODING-08",
                version="1.0.0",
                name="Repeated Percent Encoding Obfuscation",
                description="Detects double percent-encoding sequences (e.g. %25) designed to evade inspection",
                category="obfuscation",
                severity=ThreatSeverity.HIGH,
                weight=0.55,
                enabled=True,
            ),
            "HR-SUSPICIOUS-TLD-09": HeuristicRule(
                rule_id="HR-SUSPICIOUS-TLD-09",
                version="1.0.0",
                name="High-Abuse Top-Level Domain",
                description="Detects domains registered on top-level domains with established high malicious ratios",
                category="reputation",
                severity=ThreatSeverity.LOW,
                weight=0.20,
                enabled=True,
            ),
            "HR-LONG-URL-10": HeuristicRule(
                rule_id="HR-LONG-URL-10",
                version="1.0.0",
                name="Abnormal URL Length and Entropy",
                description="Detects disproportionately long URLs with high character entropy in path/query",
                category="structure",
                severity=ThreatSeverity.LOW,
                weight=0.15,
                enabled=True,
            ),
            "HR-KNOWN-GOOD-WHITELIST-00": HeuristicRule(
                rule_id="HR-KNOWN-GOOD-WHITELIST-00",
                version="1.0.0",
                name="Trusted Top Domain Whitelist",
                description="Dampens risk score when destination is a verified legitimate infrastructure domain",
                category="whitelist",
                severity=ThreatSeverity.NONE,
                weight=-0.90,  # Negative weight provides strong dampening
                enabled=True,
            ),
        }

    def _apply_overrides(self, overrides: dict[str, dict[str, Any]]) -> None:
        for rule_id, settings in overrides.items():
            if rule_id in self.rules:
                rule = self.rules[rule_id]
                if "enabled" in settings:
                    rule.enabled = bool(settings["enabled"])
                if "weight" in settings:
                    rule.weight = float(settings["weight"])
                if "severity" in settings and isinstance(settings["severity"], ThreatSeverity):
                    rule.severity = settings["severity"]

    def analyze(self, url: NormalizedURL) -> list[EvidenceItem]:
        """Evaluate a NormalizedURL and return verifiable evidence items."""
        evidence: list[EvidenceItem] = []

        # 0. Check Whitelist
        if self._is_whitelisted(url):
            rule = self.rules["HR-KNOWN-GOOD-WHITELIST-00"]
            if rule.enabled:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] Registrable domain '{url.domain}' matches verified trusted baseline.",
                        severity=rule.severity,
                        confidence=0.99,
                    )
                )
            return evidence  # Known-good whitelist skips adversarial heuristics

        # 1. Homoglyphs & Punycode
        if url.is_punycode:
            rule = self.rules["HR-HOMOGLYPH-01"]
            if rule.enabled:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] Domain '{url.host}' uses IDN Punycode encoding representing '{url.unicode_host}'.",
                        severity=rule.severity,
                        confidence=0.88,
                    )
                )

        # 2. Embedded Credentials Spoofing
        if url.has_embedded_credentials:
            rule = self.rules["HR-CREDENTIAL-SPOOF-02"]
            if rule.enabled:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] Authority section contains userinfo ('{url.userinfo}'), which frequently disguises destination '{url.host}'.",
                        severity=rule.severity,
                        confidence=0.95,
                    )
                )

        # 3. Direct IP Address Host
        if url.is_ip_literal:
            rule = self.rules["HR-IP-HOST-03"]
            if rule.enabled:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] URL uses literal IP address '{url.host}' as destination instead of a registered domain.",
                        severity=rule.severity,
                        confidence=0.80,
                    )
                )

        # 4. Suspicious / Non-standard Ports
        if url.port is not None and url.port not in {80, 443, 8080, 8443}:
            rule = self.rules["HR-SUSPICIOUS-PORT-04"]
            if rule.enabled:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] URL connects on non-standard port :{url.port}.",
                        severity=rule.severity,
                        confidence=0.70,
                    )
                )

        # 5. Excessive Subdomain Depth
        if len(url.subdomains) >= 3:
            rule = self.rules["HR-EXCESSIVE-SUBDOMAINS-05"]
            if rule.enabled:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] Deep subdomain nesting detected ({len(url.subdomains)} levels: {'.'.join(url.subdomains)}).",
                        severity=rule.severity,
                        confidence=0.60,
                    )
                )

        # 6. Brand Impersonation / Mimicry
        brand_impersonated = self._check_brand_impersonation(url)
        if brand_impersonated:
            rule = self.rules["HR-BRAND-IMPERSONATION-06"]
            if rule.enabled:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] Target displays lexical brand mimicry of '{brand_impersonated}' on unauthorized domain '{url.domain}'.",
                        severity=rule.severity,
                        confidence=0.85,
                    )
                )

        # 7. Credential Harvesting Action Keywords
        matched_keywords = self._check_phish_keywords(url)
        if matched_keywords:
            rule = self.rules["HR-PHISH-KEYWORDS-07"]
            if rule.enabled:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] URL path/subdomains contain credential-action keywords: {', '.join(matched_keywords)}.",
                        severity=rule.severity,
                        confidence=0.72,
                    )
                )

        # 8. Repeated / Double Percent Encoding
        if "%25" in url.raw_input.lower() or "%00" in url.raw_input.lower():
            rule = self.rules["HR-DOUBLE-ENCODING-08"]
            if rule.enabled:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] Double percent-encoding or null-byte escape sequence detected in input string.",
                        severity=rule.severity,
                        confidence=0.90,
                    )
                )

        # 9. Suspicious TLD
        tld = url.domain.split(".")[-1].lower() if "." in url.domain else ""
        if tld in SUSPICIOUS_TLDS:
            rule = self.rules["HR-SUSPICIOUS-TLD-09"]
            if rule.enabled:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] Registrable domain uses high-abuse top-level domain '.{tld}'.",
                        severity=rule.severity,
                        confidence=0.55,
                    )
                )

        # 10. Long URL & Path Entropy
        if len(url.canonical_url) >= 200:
            rule = self.rules["HR-LONG-URL-10"]
            entropy = self._shannon_entropy(url.path)
            if rule.enabled and entropy > 3.8:
                evidence.append(
                    EvidenceItem(
                        category=rule.category,
                        reason=f"[{rule.rule_id}] URL exhibits abnormal length ({len(url.canonical_url)} chars) with high path entropy ({entropy:.2f}).",
                        severity=rule.severity,
                        confidence=0.50,
                    )
                )

        return evidence

    @classmethod
    def _is_whitelisted(cls, url: NormalizedURL) -> bool:
        return url.domain.lower() in TRUSTED_TOP_DOMAINS

    @classmethod
    def _check_brand_impersonation(cls, url: NormalizedURL) -> str | None:
        """Check if URL targets a known brand while being hosted on an unauthorized domain."""
        target_str = f"{'.'.join(url.subdomains)} {url.path}".lower()
        for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
            # If domain is an official domain of the brand, it's legitimate
            if any(
                url.domain.lower() == od or url.domain.lower().endswith(f".{od}")
                for od in official_domains
            ):
                continue

            # Check if brand token appears in subdomains or path segments
            pattern = rf"(^|[._\-/]){re.escape(brand)}([._\-/]|$)"
            if re.search(pattern, target_str):
                return brand

        return None

    @classmethod
    def _check_phish_keywords(cls, url: NormalizedURL) -> list[str]:
        target_str = f"{'.'.join(url.subdomains)} {url.path}".lower()
        matched: list[str] = []
        for kw in PHISHING_KEYWORDS:
            if kw in target_str:
                matched.append(kw)
        return matched

    @classmethod
    def _shannon_entropy(cls, text: str) -> float:
        if not text:
            return 0.0
        frequencies = {c: text.count(c) / len(text) for c in set(text)}
        return -sum(p * math.log2(p) for p in frequencies.values() if p > 0)
