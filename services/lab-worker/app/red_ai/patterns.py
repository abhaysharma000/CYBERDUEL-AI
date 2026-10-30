"""Threat Pattern Library containing versioned synthetic threat patterns and benign controls.

CRITICAL SAFETY BOUNDARY:
All patterns in this library are strictly harmless synthetic templates using reserved
documentation domains (.test, .example, example.com) and documentation IP ranges (RFC 5737 / RFC 3849).
Zero live malicious infrastructure or executable malware payloads are contained here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cyberduel_contracts.enums import Decision, ExpectedClass, ScenarioFamily


@dataclass(frozen=True)
class ThreatPatternTemplate:
    """Immutable specification for a synthetic threat scenario or benign control."""

    template_id: str
    family: ScenarioFamily
    name: str
    description: str
    raw_url: str
    expected_class: ExpectedClass
    expected_decision: Decision
    difficulty: str  # "basic", "intermediate", "advanced", "adversarial"
    expected_evidence: list[str]
    tags: list[str] = field(default_factory=list)
    rationale: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ThreatPatternLibrary:
    """Catalog of versioned synthetic patterns covering all defensive detection vectors."""

    VERSION = "1.0.0"

    _PATTERNS: list[ThreatPatternTemplate] = [
        # 1. Homograph Mimicry
        ThreatPatternTemplate(
            template_id="PAT-HOMO-001",
            family=ScenarioFamily.HOMOGRAPH_MIMICRY,
            name="Cyrillic PayPal Homoglyph Mimicry",
            description="Domain using Cyrillic small 'a' (U+0430) mimicking PayPal brand",
            raw_url="https://xn--pypal-4ve.example.test/signin",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            difficulty="intermediate",
            expected_evidence=["homoglyph", "brand_impersonation"],
            tags=["homograph", "punycode", "brand_theft"],
            rationale="Cyrillic homoglyph on unverified domain targeting credential harvest.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-HOMO-002",
            family=ScenarioFamily.HOMOGRAPH_MIMICRY,
            name="Greek Google Homoglyph Mimicry",
            description="Domain using Greek omicron mimicking Google brand",
            raw_url="https://xn--gogle-l1a.example.test/accounts",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            difficulty="intermediate",
            expected_evidence=["homoglyph", "brand_impersonation"],
            tags=["homograph", "punycode", "google"],
            rationale="Greek omicron substitution designed to bypass visual user inspection.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-HOMO-003",
            family=ScenarioFamily.HOMOGRAPH_MIMICRY,
            name="Cyrillic Apple Homoglyph Portal",
            description="Domain using Cyrillic small 'a' targeting Apple ID login",
            raw_url="https://xn--pple-43d.example.test/id/login",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            difficulty="intermediate",
            expected_evidence=["homoglyph", "brand_impersonation"],
            tags=["homograph", "apple", "punycode"],
            rationale="Homoglyph variation on consumer brand portal.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-HOMO-004",
            family=ScenarioFamily.HOMOGRAPH_MIMICRY,
            name="Cyrillic Microsoft Homoglyph Verification",
            description="Domain using Cyrillic small 'o' (U+043E) mimicking Microsoft",
            raw_url="https://xn--micrsft-90a4j.example.test/auth",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            difficulty="advanced",
            expected_evidence=["homoglyph", "brand_impersonation"],
            tags=["homograph", "microsoft", "punycode"],
            rationale="Multi-character homoglyph evasion attempt.",
        ),
        # 2. Authority Spoofing (Embedded Credentials)
        ThreatPatternTemplate(
            template_id="PAT-AUTH-001",
            family=ScenarioFamily.AUTHORITY_SPOOFING,
            name="PayPal Authority Userinfo Spoof",
            description="URL userinfo disguises true destination server",
            raw_url="https://paypal.com@secure-account-center.example.test/login",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            difficulty="basic",
            expected_evidence=["authority_spoof", "brand_impersonation"],
            tags=["userinfo", "authority_spoof", "phishing"],
            rationale="Classic RFC 3986 userinfo confusion attack.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-AUTH-002",
            family=ScenarioFamily.AUTHORITY_SPOOFING,
            name="Google Account Authority Userinfo Spoof",
            description="URL userinfo credentials containing google.com account token",
            raw_url="https://google.com:auth-token@unverified-relay.example.test/session",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            difficulty="intermediate",
            expected_evidence=["authority_spoof", "brand_impersonation"],
            tags=["userinfo", "credentials", "google"],
            rationale="Authority credentials designed to mislead browser address bar parsing.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-AUTH-003",
            family=ScenarioFamily.AUTHORITY_SPOOFING,
            name="Bank Verification Userinfo Spoof",
            description="Authority section spoofing internal banking portal",
            raw_url="https://internal-bank.com@gateway-proxy.example.test/transfer",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            difficulty="intermediate",
            expected_evidence=["authority_spoof"],
            tags=["userinfo", "financial", "spoof"],
            rationale="Disguises hostile gateway host behind trusted bank authority string.",
        ),
        # 3. IP Host Literals
        ThreatPatternTemplate(
            template_id="PAT-IP-001",
            family=ScenarioFamily.IP_HOST,
            name="IPv4 Documentation Address Host",
            description="Direct connection to IPv4 documentation address without DNS",
            raw_url="http://192.0.2.10/admin/panel",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="basic",
            expected_evidence=["ip_address_host"],
            tags=["ipv4", "direct_ip", "network_anomaly"],
            rationale="Direct IP connection circumvents domain reputation checks.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-IP-002",
            family=ScenarioFamily.IP_HOST,
            name="IPv4 Documentation Address with Non-standard Port",
            description="Direct connection to IPv4 on port 8080 with login keyword",
            raw_url="http://198.51.100.42:8080/secure/login",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            difficulty="intermediate",
            expected_evidence=["ip_address_host", "network_anomaly", "phishing_keywords"],
            tags=["ipv4", "port_8080", "login_keywords"],
            rationale="Compound threat: raw IP + alternative port + credential theft keyword.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-IP-003",
            family=ScenarioFamily.IP_HOST,
            name="IPv6 Bracketed Documentation Address",
            description="Bracketed IPv6 literal target using documentation prefix",
            raw_url="http://[2001:db8::1]/command-center",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="intermediate",
            expected_evidence=["ip_address_host"],
            tags=["ipv6", "literal_host", "rfc3849"],
            rationale="Direct IPv6 bypasses standard host reputation.",
        ),
        # 4. Brand Impersonation
        ThreatPatternTemplate(
            template_id="PAT-BRAND-001",
            family=ScenarioFamily.BRAND_IMPERSONATION,
            name="PayPal Deep Subdomain Impersonation",
            description="High-value brand token placed as subdomain label",
            raw_url="https://paypal.account-recovery-system.example.test/verify",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            difficulty="basic",
            expected_evidence=["brand_impersonation"],
            tags=["brand", "paypal", "subdomain"],
            rationale="Brand token on unregistered second-level domain.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-BRAND-002",
            family=ScenarioFamily.BRAND_IMPERSONATION,
            name="Microsoft Security Update Path Token",
            description="Microsoft brand in path combined with urgency keywords",
            raw_url="https://portal-notice.example.test/microsoft-office365-security/update",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="intermediate",
            expected_evidence=["brand_impersonation", "phishing_keywords"],
            tags=["brand", "microsoft", "path_token"],
            rationale="Path-level brand mimicry paired with software update deception.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-BRAND-003",
            family=ScenarioFamily.BRAND_IMPERSONATION,
            name="Apple iCloud Verification Token",
            description="iCloud brand label embedded in deceptive third-level domain",
            raw_url="https://apple.icloud-locate-device.example.test/map",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.BLOCK,
            difficulty="intermediate",
            expected_evidence=["brand_impersonation"],
            tags=["apple", "icloud", "brand_theft"],
            rationale="Leverages brand familiarity to induce credential submission.",
        ),
        # 5. Suspicious Non-Standard Ports
        ThreatPatternTemplate(
            template_id="PAT-PORT-001",
            family=ScenarioFamily.SUSPICIOUS_PORT,
            name="Proxy Port 3128 Anomaly",
            description="Target server operating on standard proxy port 3128",
            raw_url="http://auth-relay.example.test:3128/connect",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="intermediate",
            expected_evidence=["network_anomaly"],
            tags=["port", "proxy_3128", "network_anomaly"],
            rationale="Traffic directed to common open proxy port.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-PORT-002",
            family=ScenarioFamily.SUSPICIOUS_PORT,
            name="High Alternate Port 8888 Admin Portal",
            description="Web administration endpoint exposed on port 8888",
            raw_url="http://infrastructure-node.example.test:8888/login",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="basic",
            expected_evidence=["network_anomaly"],
            tags=["port", "port_8888", "admin"],
            rationale="Evasive deployment on non-standard administration port.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-PORT-003",
            family=ScenarioFamily.SUSPICIOUS_PORT,
            name="Port 9000 Microservice Endpoint",
            description="Direct link to internal API listener on port 9000",
            raw_url="http://internal-telemetry.example.test:9000/api",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="basic",
            expected_evidence=["network_anomaly"],
            tags=["port", "port_9000"],
            rationale="Direct link bypassing standard web application firewall ports.",
        ),
        # 6. Double Encoding
        ThreatPatternTemplate(
            template_id="PAT-ENC-001",
            family=ScenarioFamily.DOUBLE_ENCODING,
            name="Double Encoded Dot-Dot Slash Path",
            description="Nested percent-encoding of path traversal tokens (%252e%252e)",
            raw_url="https://secure-storage.example.test/files/%252e%252e/%252e%252e/config",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.WARN,
            difficulty="advanced",
            expected_evidence=["evasion_technique"],
            tags=["encoding", "traversal", "evasion"],
            rationale="Double percent encoding intended to bypass web server URL decoders.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-ENC-002",
            family=ScenarioFamily.DOUBLE_ENCODING,
            name="Double Encoded Query Parameter",
            description="Nested percent-encoding inside redirection query parameter",
            raw_url="https://redirect-service.example.test/bounce?dest=https%253A%252F%252Fbad.test",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="advanced",
            expected_evidence=["evasion_technique"],
            tags=["encoding", "open_redirect"],
            rationale="Hides destination target from naive single-pass inspection filters.",
        ),
        # 7. DGA & High Entropy
        ThreatPatternTemplate(
            template_id="PAT-DGA-001",
            family=ScenarioFamily.DGA_ENTROPY,
            name="High Entropy DGA Hostname 1",
            description="Pseudo-random domain name generated by algorithmic seeding",
            raw_url="https://qzxwkjhgf9876lkjh.example.test/sync",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="intermediate",
            expected_evidence=["domain_entropy"],
            tags=["dga", "entropy", "algorithm"],
            rationale="Shannon entropy exceeds 3.8 bits/character.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-DGA-002",
            family=ScenarioFamily.DGA_ENTROPY,
            name="Compound DGA Subdomain",
            description="Random alphanumeric subdomains stacked above registered domain",
            raw_url="https://x89f72b9a4c1e03.dga-tracker.example.test/beacon",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="intermediate",
            expected_evidence=["domain_entropy"],
            tags=["dga", "entropy", "subdomain"],
            rationale="High-entropy label indicating automated botnet rendezvous.",
        ),
        # 8. Subdomain Flooding
        ThreatPatternTemplate(
            template_id="PAT-SUB-001",
            family=ScenarioFamily.SUBDOMAIN_FLOODING,
            name="Deep Five-Label Subdomain Chain",
            description="Domain nesting with 5 consecutive subdomain labels",
            raw_url="https://a.b.c.d.e.gateway.example.test/index",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="basic",
            expected_evidence=["dns_obfuscation"],
            tags=["subdomain", "dns_nesting", "obfuscation"],
            rationale="Intended to push primary domain out of mobile or address bar display.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-SUB-002",
            family=ScenarioFamily.SUBDOMAIN_FLOODING,
            name="Brand Stacked Deep Subdomain",
            description="Deep subdomain chain embedding trusted brand label at the edge",
            raw_url="https://login.security.account.update.auth.example.test/session",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="intermediate",
            expected_evidence=["dns_obfuscation", "phishing_keywords"],
            tags=["subdomain", "phishing_keywords"],
            rationale="Multiple levels of trust-inducing keywords masking origin.",
        ),
        # 9. Length Anomalies
        ThreatPatternTemplate(
            template_id="PAT-LEN-001",
            family=ScenarioFamily.LENGTH_ANOMALY,
            name="Excessively Long URL with Repeated Tokens",
            description="URL exceeding 280 characters with deep repeating path segments",
            raw_url="https://content-delivery.example.test/session/v1/auth/path/verification/client/token/redirect/action/state/identifier/payload/data/resource/item/element/node/leaf/status/complete/final/check?session_tracker_id=1234567890&tracking_source=email_campaign_newsletter_blast",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="basic",
            expected_evidence=["structural_anomaly"],
            tags=["length", "structural_anomaly", "deep_path"],
            rationale="URL exceeds 255-character benchmark anomaly ceiling.",
        ),
        # 10. Phishing Lexical Keywords
        ThreatPatternTemplate(
            template_id="PAT-KEYW-001",
            family=ScenarioFamily.PHISHING_KEYWORDS,
            name="Multi-keyword Credential Harvesting Path",
            description="Target URL combines multiple high-risk credential theft keywords",
            raw_url="https://account-verify-support.example.test/banking/secure/login/update-credentials",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.WARN,
            difficulty="basic",
            expected_evidence=["phishing_keywords"],
            tags=["keywords", "banking", "login"],
            rationale="Dense concentration of credential harvesting terminology.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-KEYW-002",
            family=ScenarioFamily.PHISHING_KEYWORDS,
            name="Wallet Password Reset Phishing Path",
            description="Path combines wallet, password, and identity verification terms",
            raw_url="https://crypto-portal-notice.example.test/wallet/password/verify-identity",
            expected_class=ExpectedClass.MALICIOUS,
            expected_decision=Decision.WARN,
            difficulty="intermediate",
            expected_evidence=["phishing_keywords"],
            tags=["keywords", "wallet", "crypto"],
            rationale="Financial asset access harvesting pattern.",
        ),
        # 11. Benign Lookalikes (Crucial False Positive Control)
        ThreatPatternTemplate(
            template_id="PAT-LOOK-001",
            family=ScenarioFamily.BENIGN_LOOKALIKE,
            name="Benign PayPal Gift Shop",
            description="Legitimate business containing paypal substring in a hyphenated domain",
            raw_url="https://my-paypals-giftshop.example.test/catalog",
            expected_class=ExpectedClass.BENIGN,
            expected_decision=Decision.ALLOW,
            difficulty="adversarial",
            expected_evidence=[],
            tags=["benign_control", "false_positive_test", "substring"],
            rationale="Must not trigger false positive merely because domain has 'paypal' substring.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-LOOK-002",
            family=ScenarioFamily.BENIGN_LOOKALIKE,
            name="Benign Documentation Update Guide",
            description="Legitimate developer documentation with 'update' and 'login' in path",
            raw_url="https://docs.development.example.test/guide/user-login/software-update",
            expected_class=ExpectedClass.BENIGN,
            expected_decision=Decision.ALLOW,
            difficulty="intermediate",
            expected_evidence=[],
            tags=["benign_control", "developer_docs", "keywords"],
            rationale="Educational/technical documentation referencing login mechanisms safely.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-LOOK-003",
            family=ScenarioFamily.BENIGN_LOOKALIKE,
            name="Benign Engineering Port 8080 Test Server",
            description="Legitimate internal engineering staging server on port 8080",
            raw_url="https://engineering-staging.example.test:8080/health",
            expected_class=ExpectedClass.BENIGN,
            expected_decision=Decision.WARN,
            difficulty="intermediate",
            expected_evidence=["network_anomaly"],
            tags=["benign_control", "port_8080", "staging"],
            rationale="Non-standard port is suspicious but within policy warning bounds.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-LOOK-004",
            family=ScenarioFamily.BENIGN_LOOKALIKE,
            name="Benign Apple Fan Club News",
            description="Third-party community fan blog discussing Apple updates",
            raw_url="https://apple-enthusiasts-club.example.test/articles/latest",
            expected_class=ExpectedClass.BENIGN,
            expected_decision=Decision.ALLOW,
            difficulty="adversarial",
            expected_evidence=[],
            tags=["benign_control", "fan_club", "editorial"],
            rationale="Editorial brand reference on distinct registrable domain.",
        ),
        # 12. Whitelist Controls
        ThreatPatternTemplate(
            template_id="PAT-WHITE-001",
            family=ScenarioFamily.WHITELIST_CONTROL,
            name="Authoritative Google Search Endpoint",
            description="Authoritative whitelisted search endpoint",
            raw_url="https://google.com/search?q=cybersecurity+defense",
            expected_class=ExpectedClass.BENIGN,
            expected_decision=Decision.ALLOW,
            difficulty="basic",
            expected_evidence=["whitelist"],
            tags=["whitelist", "authoritative", "google"],
            rationale="Authoritative domain override rule.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-WHITE-002",
            family=ScenarioFamily.WHITELIST_CONTROL,
            name="Authoritative GitHub Repository URL",
            description="Authoritative whitelisted GitHub repository",
            raw_url="https://github.com/cyberduel-ai/platform",
            expected_class=ExpectedClass.BENIGN,
            expected_decision=Decision.ALLOW,
            difficulty="basic",
            expected_evidence=["whitelist"],
            tags=["whitelist", "authoritative", "github"],
            rationale="Authoritative domain override rule.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-WHITE-003",
            family=ScenarioFamily.WHITELIST_CONTROL,
            name="Authoritative Microsoft TechNet Guide",
            description="Authoritative Microsoft documentation guide",
            raw_url="https://microsoft.com/en-us/security/engineering",
            expected_class=ExpectedClass.BENIGN,
            expected_decision=Decision.ALLOW,
            difficulty="basic",
            expected_evidence=["whitelist"],
            tags=["whitelist", "authoritative", "microsoft"],
            rationale="Authoritative domain override rule.",
        ),
        # 13. Normalization Edge Cases
        ThreatPatternTemplate(
            template_id="PAT-NORM-001",
            family=ScenarioFamily.NORMALIZATION_EDGE_CASE,
            name="Mixed Casing and Default HTTPS Port",
            description="Uppercase scheme, mixed case host, and explicit port 443",
            raw_url="HTTPS://Docs.Example.TEST:443/API/V1/Resources",
            expected_class=ExpectedClass.BENIGN,
            expected_decision=Decision.ALLOW,
            difficulty="intermediate",
            expected_evidence=[],
            tags=["normalization", "casing", "port_443"],
            rationale="Normalizer must canonicalize casing and strip default port.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-NORM-002",
            family=ScenarioFamily.NORMALIZATION_EDGE_CASE,
            name="Dot-Segment Path Traversal Resolution",
            description="Legitimate path with benign relative dot-segments /a/b/../c/./d",
            raw_url="https://content.example.test/static/css/../js/./bundle.js",
            expected_class=ExpectedClass.BENIGN,
            expected_decision=Decision.ALLOW,
            difficulty="intermediate",
            expected_evidence=[],
            tags=["normalization", "dot_segments"],
            rationale="Normalizer must resolve dot-segments to canonical /static/js/bundle.js.",
        ),
        ThreatPatternTemplate(
            template_id="PAT-NORM-003",
            family=ScenarioFamily.NORMALIZATION_EDGE_CASE,
            name="Sensitive Token Query Parameter Redaction",
            description="URL containing cleartext auth token that must be redacted",
            raw_url="https://api.example.test/v1/auth?token=supersecret12345&client=mobile",
            expected_class=ExpectedClass.BENIGN,
            expected_decision=Decision.ALLOW,
            difficulty="basic",
            expected_evidence=[],
            tags=["normalization", "privacy", "redaction"],
            rationale="Verify token is redacted in audit logs without altering classification.",
        ),
        # 14. Stale Intelligence Testing
        ThreatPatternTemplate(
            template_id="PAT-STALE-001",
            family=ScenarioFamily.STALE_INTELLIGENCE,
            name="Expired Threat Intelligence Indicator",
            description="Domain previously associated with threat activity whose indicator has expired",
            raw_url="https://stale-threat-record.example.test/archive",
            expected_class=ExpectedClass.SUSPICIOUS,
            expected_decision=Decision.WARN,
            difficulty="adversarial",
            expected_evidence=[],
            tags=["threat_intel", "staleness", "expiration"],
            rationale="Tests engine behavior when indicator expires from active verified pool.",
        ),
    ]

    @classmethod
    def list_templates(cls, family: ScenarioFamily | None = None) -> list[ThreatPatternTemplate]:
        """Return all templates, optionally filtered by scenario family."""
        if family is None:
            return list(cls._PATTERNS)
        return [p for p in cls._PATTERNS if p.family == family]

    @classmethod
    def get_template(cls, template_id: str) -> ThreatPatternTemplate | None:
        """Lookup a template by its unique template ID."""
        for p in cls._PATTERNS:
            if p.template_id == template_id:
                return p
        return None

    @classmethod
    def supported_families(cls) -> list[str]:
        """Return distinct family names represented in the library."""
        return sorted({p.family.value for p in cls._PATTERNS})
