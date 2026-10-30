"""Safe, bounded declarative rule evaluation engine for CyberDuel AI.

CRITICAL SAFETY BOUNDARY:
This engine executes strictly bounded declarative predicate logic.
It explicitly forbids:
- Python eval() or exec()
- Dynamic module imports
- Shell command execution
- Unbounded loops or recursive AST evaluation
- Unallowlisted feature access
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from cyberduel_contracts.analysis import EvidenceItem
from cyberduel_contracts.enums import Decision, ThreatSeverity
from cyberduel_contracts.policy import DeclarativeRuleModel, RulePredicateModel
from cyberduel_threat_intel.feature_extractor import URLFeatureExtractor
from cyberduel_threat_intel.normalizer import NormalizedURL

logger = logging.getLogger("declarative_rules")


class RuleValidationError(Exception):
    """Raised when a declarative rule violates schema, bounds, or allowlist constraints."""


@dataclass(frozen=True)
class RuleEvaluationOutcome:
    """Result of evaluating a declarative rule against a target URL."""

    matched: bool
    rule_id: str
    rule_version: str
    action: Decision
    severity: ThreatSeverity
    weight: float
    evidence: EvidenceItem | None = None
    reason: str = ""


class DeclarativeRuleEngine:
    """Evaluates declarative rules over normalized URLs and deterministic feature maps."""

    ALLOWED_FEATURES = {
        "url_length",
        "host_length",
        "path_length",
        "query_length",
        "subdomain_count",
        "path_depth",
        "has_embedded_credentials",
        "is_ip_literal",
        "is_punycode",
        "brand_token_detected",
        "has_non_standard_port",
        "has_double_encoding",
        "phish_keyword_count",
        "host_entropy",
        "scheme",
        "host",
        "unicode_host",
        "port",
        "domain",
        "is_whitelisted",
    }

    ALLOWED_OPERATORS = {
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

    MAX_PREDICATES_PER_RULE = 10
    MAX_REGEX_PATTERN_LENGTH = 128

    @classmethod
    def validate_rule(cls, rule: DeclarativeRuleModel) -> bool:
        """Enforce strict compile-time validation on declarative rules."""
        if len(rule.predicates) == 0:
            raise RuleValidationError(f"Rule '{rule.rule_id}' has no predicates.")

        if len(rule.predicates) > cls.MAX_PREDICATES_PER_RULE:
            raise RuleValidationError(
                f"Rule '{rule.rule_id}' exceeds maximum predicate count ({cls.MAX_PREDICATES_PER_RULE})."
            )

        for p in rule.predicates:
            if p.field not in cls.ALLOWED_FEATURES:
                raise RuleValidationError(
                    f"Rule '{rule.rule_id}' references unallowlisted feature: '{p.field}'."
                )

            if p.operator not in cls.ALLOWED_OPERATORS:
                raise RuleValidationError(
                    f"Rule '{rule.rule_id}' uses unsupported operator: '{p.operator}'."
                )

            if p.operator == "matches_regex":
                if not isinstance(p.value, str):
                    raise RuleValidationError(
                        f"matches_regex requires string value in '{rule.rule_id}'."
                    )
                if len(p.value) > cls.MAX_REGEX_PATTERN_LENGTH:
                    raise RuleValidationError(
                        f"Regex pattern exceeds max length {cls.MAX_REGEX_PATTERN_LENGTH} in '{rule.rule_id}'."
                    )
                # ReDoS vulnerability check for nested quantifiers
                if re.search(r"\([^)]*[\+\*]\)[\+\*]", p.value) or re.search(
                    r"(\+|\*|\{[0-9]+,\})\s*(\+|\*|\{[0-9]+,\})", p.value
                ):
                    raise RuleValidationError(
                        f"ReDoS vulnerability detected in regex '{p.value}' for rule '{rule.rule_id}'."
                    )
                try:
                    re.compile(p.value)
                except re.error as e:
                    raise RuleValidationError(
                        f"Invalid regex syntax '{p.value}' in '{rule.rule_id}': {e}"
                    ) from e

        return True

    @classmethod
    def evaluate_predicate(
        cls,
        predicate: RulePredicateModel,
        context: dict[str, Any],
    ) -> bool:
        """Evaluate a single atomic predicate against extracted feature context."""
        field_val = context.get(predicate.field)
        target_val = predicate.value
        op = predicate.operator

        if op == "eq":
            return bool(field_val == target_val)
        if op == "ne":
            return bool(field_val != target_val)
        if op == "gt":
            return bool(field_val is not None and field_val > target_val)
        if op == "gte":
            return bool(field_val is not None and field_val >= target_val)
        if op == "lt":
            return bool(field_val is not None and field_val < target_val)
        if op == "lte":
            return bool(field_val is not None and field_val <= target_val)
        if op == "contains":
            if field_val is None:
                return False
            if isinstance(field_val, (str, list, set, dict)):
                return str(target_val).lower() in str(field_val).lower()
            return False
        if op == "in":
            if isinstance(target_val, (list, set, tuple)):
                return field_val in target_val
            return False
        if op == "matches_regex":
            if field_val is None:
                return False
            return bool(re.search(str(target_val), str(field_val), re.IGNORECASE))

        return False

    @classmethod
    def evaluate_rule(
        cls,
        rule: DeclarativeRuleModel,
        url: NormalizedURL,
        feature_context: dict[str, Any] | None = None,
    ) -> RuleEvaluationOutcome:
        """Evaluate a full declarative rule over a normalized URL."""
        # Validate rule structure
        cls.validate_rule(rule)

        # Assemble full context
        if feature_context is None:
            features = URLFeatureExtractor.extract_features(url)
        else:
            features = dict(feature_context)

        # Enrich with normalized URL properties
        features.update(
            {
                "scheme": url.scheme,
                "host": url.host,
                "unicode_host": url.unicode_host,
                "port": url.port,
                "domain": url.domain,
                "url_length": len(url.canonical_url),
                "host_length": len(url.host),
                "path_length": len(url.path),
                "query_length": len(url.query) if url.query else 0,
                "subdomain_count": len(url.subdomains),
                "path_depth": len([p for p in url.path.split("/") if p]),
                "has_embedded_credentials": url.has_embedded_credentials,
                "is_ip_literal": url.is_ip_literal,
                "is_punycode": url.is_punycode,
            }
        )

        # Evaluate predicates under logical operator
        results = [cls.evaluate_predicate(p, features) for p in rule.predicates]

        matched = all(results) if rule.logical_operator == "AND" else any(results)

        evidence = None
        reason = ""
        if matched:
            reason = f"Rule [{rule.rule_id}] matched: {rule.description}"
            evidence = EvidenceItem(
                category=rule.target_family,
                reason=reason,
                severity=rule.severity,
                confidence=rule.weight,
            )

        return RuleEvaluationOutcome(
            matched=matched,
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            action=rule.action,
            severity=rule.severity,
            weight=rule.weight,
            evidence=evidence,
            reason=reason,
        )

    @classmethod
    def check_interaction_conflicts(
        cls,
        candidate_rule: DeclarativeRuleModel,
        existing_rules: list[DeclarativeRuleModel],
    ) -> dict[str, Any]:
        """Analyze potential conflicts, duplicates, or shadowing with existing rules."""
        cls.validate_rule(candidate_rule)
        conflicts = []
        is_duplicate = False

        for ex in existing_rules:
            # Check duplicate rule ID
            if (
                ex.rule_id == candidate_rule.rule_id
                and ex.rule_version == candidate_rule.rule_version
            ):
                is_duplicate = True
                conflicts.append(f"Exact rule ID & version match: '{ex.rule_id}'")

            # Check identical predicate set
            if (
                ex.target_family == candidate_rule.target_family
                and ex.predicates == candidate_rule.predicates
                and ex.logical_operator == candidate_rule.logical_operator
            ):
                is_duplicate = True
                conflicts.append(f"Identical predicate definition as rule '{ex.rule_id}'")

            # Check contradictory actions on identical predicates
            if ex.predicates == candidate_rule.predicates and ex.action != candidate_rule.action:
                conflicts.append(
                    f"Contradictory action: Candidate specifies '{candidate_rule.action}' "
                    f"but existing rule '{ex.rule_id}' specifies '{ex.action}'"
                )

        return {
            "has_conflicts": len(conflicts) > 0,
            "is_duplicate": is_duplicate,
            "conflicts": conflicts,
        }

    @classmethod
    def find_rule_conflicts(cls, rules: list[DeclarativeRuleModel]) -> list[str]:
        """Find contradictory or conflicting rules across a list of rules."""
        conflicts = []
        for i, r1 in enumerate(rules):
            for r2 in rules[i + 1 :]:
                res = cls.check_interaction_conflicts(r1, [r2])
                if res["has_conflicts"]:
                    conflicts.extend(res["conflicts"])
        return conflicts
