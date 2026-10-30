"""Exportable, machine-readable defensive policy bundle generator for edge clients."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class DeclarativeRuleSpec(BaseModel):
    """Specification of an edge-executable declarative heuristic or signature rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    version: str
    pattern_type: str  # "regex", "exact_hash", "bloom", "keyword_list"
    pattern: str | list[str]
    severity: str
    action: str  # "block", "warn", "allow"
    description: str


class LocalProtectionPolicyBundle(BaseModel):
    """Machine-readable policy package consumable by browser extensions and mobile clients."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = Field(default="1.0.0", description="Policy format specification version")
    policy_id: str = Field(description="Unique UUID string for this compiled policy package")
    policy_version: str = Field(
        description="Semantic or calendar version string (e.g. '2026.10.1')"
    )
    issued_at: datetime = Field(description="UTC timestamp when the policy bundle was compiled")
    expires_at: datetime = Field(
        description="UTC timestamp after which clients must refresh policy"
    )
    min_client_version: str = Field(default="0.1.0", description="Minimum supported client version")
    blacklisted_domain_hashes: list[str] = Field(
        default_factory=list,
        description="SHA-256 hashes of confirmed malicious domain names for O(1) bloom/set lookup",
    )
    whitelisted_domain_hashes: list[str] = Field(
        default_factory=list,
        description="SHA-256 hashes of verified trusted domains for immediate bypass",
    )
    declarative_rules: list[DeclarativeRuleSpec] = Field(
        default_factory=list,
        description="Client-evaluable declarative regex and lexical heuristics",
    )
    rules_digest: str = Field(
        description="SHA-256 integrity digest computed over the canonical rules payload",
    )


class PolicyBundleExporter:
    """Compiles active threat intelligence and declarative heuristic rules into edge policy bundles."""

    @classmethod
    def create_bundle(
        cls,
        policy_version: str = "2026.10.1",
        ttl_days: int = 14,
        blacklisted_domains: list[str] | None = None,
        whitelisted_domains: list[str] | None = None,
        declarative_rules: list[DeclarativeRuleSpec] | None = None,
    ) -> LocalProtectionPolicyBundle:
        """Create a versioned policy bundle with integrity digest."""
        now = datetime.now(UTC)
        expires = now + timedelta(days=ttl_days)
        policy_id = str(uuid4())

        # Hash domain indicators
        blacklisted_hashes = sorted(
            {
                hashlib.sha256(d.strip().lower().encode("utf-8")).hexdigest()
                for d in (blacklisted_domains or [])
                if d.strip()
            }
        )
        whitelisted_hashes = sorted(
            {
                hashlib.sha256(d.strip().lower().encode("utf-8")).hexdigest()
                for d in (whitelisted_domains or [])
                if d.strip()
            }
        )

        # Baseline declarative rules if not provided
        rules = declarative_rules or cls._default_declarative_rules()

        # Compute rules digest over canonical JSON representation of rules & indicators
        payload_to_hash = {
            "policy_version": policy_version,
            "blacklisted_hashes": blacklisted_hashes,
            "whitelisted_hashes": whitelisted_hashes,
            "rules": [r.model_dump(mode="json") for r in rules],
        }
        canonical_json = json.dumps(payload_to_hash, sort_keys=True)
        rules_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        return LocalProtectionPolicyBundle(
            format_version="1.0.0",
            policy_id=policy_id,
            policy_version=policy_version,
            issued_at=now,
            expires_at=expires,
            min_client_version="0.1.0",
            blacklisted_domain_hashes=blacklisted_hashes,
            whitelisted_domain_hashes=whitelisted_hashes,
            declarative_rules=rules,
            rules_digest=rules_digest,
        )

    @classmethod
    def verify_bundle_integrity(cls, bundle: LocalProtectionPolicyBundle) -> bool:
        """Verify that the bundle's rules digest matches its contents."""
        payload_to_hash = {
            "policy_version": bundle.policy_version,
            "blacklisted_hashes": bundle.blacklisted_domain_hashes,
            "whitelisted_hashes": bundle.whitelisted_domain_hashes,
            "rules": [r.model_dump(mode="json") for r in bundle.declarative_rules],
        }
        canonical_json = json.dumps(payload_to_hash, sort_keys=True)
        expected_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        return bundle.rules_digest == expected_digest

    @classmethod
    def _default_declarative_rules(cls) -> list[DeclarativeRuleSpec]:
        return [
            DeclarativeRuleSpec(
                rule_id="EDGE-PUNYCODE-01",
                version="1.0.0",
                pattern_type="regex",
                pattern=r"(^|[.])xn--",
                severity="high",
                action="warn",
                description="Flags IDN Punycode domains on the client edge",
            ),
            DeclarativeRuleSpec(
                rule_id="EDGE-USERINFO-02",
                version="1.0.0",
                pattern_type="regex",
                pattern=r"^https?://[^/]+@",
                severity="critical",
                action="block",
                description="Blocks URLs with embedded credentials in authority section",
            ),
            DeclarativeRuleSpec(
                rule_id="EDGE-IP-HOST-03",
                version="1.0.0",
                pattern_type="regex",
                pattern=r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                severity="medium",
                action="warn",
                description="Warns on raw IPv4 literal destinations",
            ),
        ]
