"""Builds canonical, versioned, declarative policy bundles from evaluated candidate defenses."""

import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from cyberduel_contracts.crypto import canonicalize_json, compute_sha256
from cyberduel_contracts.policy import DeclarativeRuleModel
from cyberduel_contracts.releases import LocalProtectionPolicyBundle

SAFE_PREDICATE_OPERATORS = {
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "contains",
    "in",
    "matches_regex",
}

SAFE_FEATURE_FIELDS = {
    "url",
    "scheme",
    "domain",
    "host",
    "path",
    "query",
    "fragment",
    "port",
    "entropy",
    "length",
    "subdomain_count",
    "has_ip_host",
    "has_homoglyphs",
    "keyword_match_count",
    "suspicious_token_count",
}


class PolicyBundleValidationError(Exception):
    """Raised when candidate rules or indicators fail safety or schema validation."""


class PolicyBundleBuilder:
    """Constructs authenticated, declarative local protection bundles with zero executable code."""

    def validate_declarative_rule(
        self, rule: DeclarativeRuleModel | dict[str, Any]
    ) -> DeclarativeRuleModel:
        """Verify rule structure and ensure safety: no code execution, valid operators, compilable regex."""
        rule_model = DeclarativeRuleModel.model_validate(rule) if isinstance(rule, dict) else rule

        for predicate in rule_model.predicates:
            if predicate.operator not in SAFE_PREDICATE_OPERATORS:
                raise PolicyBundleValidationError(
                    f"Forbidden operator '{predicate.operator}' in rule '{rule_model.rule_id}'"
                )

            if predicate.operator == "matches_regex":
                if not isinstance(predicate.value, str):
                    raise PolicyBundleValidationError(
                        f"Regex predicate in rule '{rule_model.rule_id}' must be a string pattern"
                    )
                try:
                    re.compile(predicate.value)
                except re.error as e:
                    raise PolicyBundleValidationError(
                        f"Invalid regex pattern in rule '{rule_model.rule_id}': {e}"
                    ) from e

        return rule_model

    def build_bundle(
        self,
        policy_version: str,
        sequence_number: int,
        rule_spec: dict[str, Any],
        threat_indicators: list[dict[str, Any]] | None = None,
        scoring_thresholds: dict[str, float] | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
        bundle_id: UUID | None = None,
    ) -> tuple[LocalProtectionPolicyBundle, bytes, str]:
        """Compile specifications into a canonical LocalProtectionPolicyBundle.

        Returns:
            (bundle_model, canonical_bytes, sha256_digest)
        """
        raw_rules = rule_spec.get("rules", [])
        validated_rules: list[DeclarativeRuleModel] = []

        # If rule_spec is a single declarative rule or list
        if isinstance(raw_rules, list):
            for r in raw_rules:
                validated_rules.append(self.validate_declarative_rule(r))
        elif "declarative_rule" in rule_spec and rule_spec["declarative_rule"]:
            validated_rules.append(self.validate_declarative_rule(rule_spec["declarative_rule"]))

        # Extract thresholds or use defaults
        thresholds = {
            "warn_threshold": float(
                rule_spec.get(
                    "warn_threshold",
                    scoring_thresholds.get("warn_threshold", 0.50) if scoring_thresholds else 0.50,
                )
            ),
            "block_threshold": float(
                rule_spec.get(
                    "block_threshold",
                    scoring_thresholds.get("block_threshold", 0.85) if scoring_thresholds else 0.85,
                )
            ),
        }

        # Indicators validation (ensure only safe key/value representations)
        clean_indicators: list[dict[str, Any]] = []
        if threat_indicators:
            for ind in threat_indicators:
                clean_ind = {
                    "type": str(ind.get("type", "unknown")),
                    "value": str(ind.get("value", "")),
                    "severity": str(ind.get("severity", "medium")),
                    "category": str(ind.get("category", "malicious_pattern")),
                }
                clean_indicators.append(clean_ind)

        # Feature weights
        weights = {str(k): float(v) for k, v in rule_spec.get("feature_weights", {}).items()}

        now = datetime.now(UTC)
        expiry = expires_at or datetime(now.year + 1, now.month, now.day, tzinfo=UTC)

        bundle = LocalProtectionPolicyBundle(
            bundle_id=bundle_id or uuid4(),
            policy_version=policy_version,
            sequence_number=sequence_number,
            scoring_thresholds=thresholds,
            rules=validated_rules,
            threat_indicators=clean_indicators,
            feature_weights=weights,
            schema_version="1.0.0",
            created_at=now,
            expires_at=expiry,
            metadata=metadata or {"built_by": "CyberDuel-PolicyBundleBuilder-v1"},
        )

        canonical_bytes = canonicalize_json(bundle.model_dump(mode="json"))
        digest = compute_sha256(canonical_bytes)
        return bundle, canonical_bytes, digest
