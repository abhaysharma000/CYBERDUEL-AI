"""Tests for safe declarative detection rule engine and AST validator."""

import pytest
from cyberduel_contracts.enums import Decision, ThreatSeverity
from cyberduel_contracts.policy import DeclarativeRuleModel, RulePredicateModel
from cyberduel_policy_engine.rules import (
    DeclarativeRuleEngine,
    RuleValidationError,
)
from cyberduel_threat_intel.validator import URLValidator
from pydantic import ValidationError


def test_rule_validation_accepts_valid_rule() -> None:
    rule = DeclarativeRuleModel(
        rule_id="RULE-TEST-001",
        description="Detect punycode homoglyphs with keywords",
        author="BlueAI",
        purpose="Prevent IDN phishing",
        target_family="homograph_mimicry",
        feature_names=["is_punycode", "phish_keyword_count"],
        predicates=[
            RulePredicateModel(field="is_punycode", operator="eq", value=1),
            RulePredicateModel(field="phish_keyword_count", operator="gte", value=1),
        ],
        logical_operator="AND",
        action=Decision.BLOCK,
        severity=ThreatSeverity.CRITICAL,
        weight=0.90,
    )
    assert DeclarativeRuleEngine.validate_rule(rule) is True


def test_rule_validation_rejects_disallowed_feature() -> None:
    rule = DeclarativeRuleModel(
        rule_id="RULE-MAL-001",
        description="Attempt to read arbitrary attribute",
        author="Attacker",
        purpose="Exploit attempt",
        target_family="exploit",
        feature_names=["__class__"],
        predicates=[
            RulePredicateModel(field="__class__", operator="eq", value="exploit"),
        ],
        logical_operator="AND",
        action=Decision.BLOCK,
    )
    with pytest.raises(RuleValidationError, match="unallowlisted feature"):
        DeclarativeRuleEngine.validate_rule(rule)


def test_rule_validation_rejects_dangerous_regex() -> None:
    rule = DeclarativeRuleModel(
        rule_id="RULE-REDOS-001",
        description="ReDoS attack pattern",
        author="Attacker",
        purpose="ReDoS attempt",
        target_family="exploit",
        feature_names=["host"],
        predicates=[
            RulePredicateModel(field="host", operator="matches_regex", value=r"(a+)+$"),
        ],
        logical_operator="AND",
        action=Decision.BLOCK,
    )
    with pytest.raises(RuleValidationError, match="ReDoS vulnerability"):
        DeclarativeRuleEngine.validate_rule(rule)


def test_rule_validation_rejects_excessive_predicates() -> None:
    # 11 predicates (max is 10)
    with pytest.raises(ValidationError):
        DeclarativeRuleModel(
            rule_id="RULE-EXCESSIVE-001",
            description="Too many predicates",
            author="BlueAI",
            purpose="Test limit",
            target_family="test",
            feature_names=["url_length"],
            predicates=[
                RulePredicateModel(field="url_length", operator="gt", value=i) for i in range(11)
            ],
            logical_operator="AND",
            action=Decision.WARN,
        )


def test_rule_evaluation_punycode_matching() -> None:
    rule = DeclarativeRuleModel(
        rule_id="RULE-PUNYCODE-001",
        description="Block punycode domains with phishing keyword",
        author="BlueAI",
        purpose="Block IDN phishing",
        target_family="homograph_mimicry",
        feature_names=["is_punycode", "phish_keyword_count"],
        predicates=[
            RulePredicateModel(field="is_punycode", operator="eq", value=1),
            RulePredicateModel(field="phish_keyword_count", operator="gte", value=1),
        ],
        logical_operator="AND",
        action=Decision.BLOCK,
        severity=ThreatSeverity.CRITICAL,
    )

    # 1. Matching attack URL
    val_attack = URLValidator.validate("https://xn--pypal-4ve.com/signin?verify=account")
    assert val_attack.is_valid and val_attack.normalized
    outcome = DeclarativeRuleEngine.evaluate_rule(rule, val_attack.normalized)
    assert outcome.matched is True
    assert outcome.action == Decision.BLOCK
    assert outcome.evidence is not None

    # 2. Benign URL without punycode
    val_benign = URLValidator.validate("https://www.google.com/search?q=cyberduel")
    assert val_benign.is_valid and val_benign.normalized
    outcome_benign = DeclarativeRuleEngine.evaluate_rule(rule, val_benign.normalized)
    assert outcome_benign.matched is False


def test_rule_evaluation_ip_literal_and_entropy() -> None:
    rule = DeclarativeRuleModel(
        rule_id="RULE-IP-001",
        description="Block numeric IP with elevated entropy",
        author="BlueAI",
        purpose="Catch direct IP drops",
        target_family="direct_ip",
        feature_names=["is_ip_literal", "host_entropy"],
        predicates=[
            RulePredicateModel(field="is_ip_literal", operator="eq", value=1),
            RulePredicateModel(field="host_entropy", operator="gt", value=2.0),
        ],
        logical_operator="AND",
        action=Decision.BLOCK,
    )

    val_ip = URLValidator.validate("http://192.168.1.1/admin/login.php")
    assert val_ip.is_valid and val_ip.normalized
    outcome = DeclarativeRuleEngine.evaluate_rule(rule, val_ip.normalized)
    assert outcome.matched is True


def test_rule_evaluation_logical_or() -> None:
    rule = DeclarativeRuleModel(
        rule_id="RULE-OR-001",
        description="Trigger if punycode OR excessive subdomains",
        author="BlueAI",
        purpose="Multi-vector test",
        target_family="general",
        feature_names=["is_punycode", "subdomain_count"],
        predicates=[
            RulePredicateModel(field="is_punycode", operator="eq", value=1),
            RulePredicateModel(field="subdomain_count", operator="gte", value=3),
        ],
        logical_operator="OR",
        action=Decision.WARN,
    )

    # Subdomain count >= 3, but not punycode
    val_sub = URLValidator.validate("https://a.b.c.example.com/test")
    assert val_sub.is_valid and val_sub.normalized
    outcome = DeclarativeRuleEngine.evaluate_rule(rule, val_sub.normalized)
    assert outcome.matched is True
    assert outcome.action == Decision.WARN


def test_rule_conflict_detection() -> None:
    rule1 = DeclarativeRuleModel(
        rule_id="RULE-A",
        description="Rule A",
        author="BlueAI",
        purpose="Test",
        target_family="test",
        feature_names=["is_punycode"],
        predicates=[RulePredicateModel(field="is_punycode", operator="eq", value=1)],
        action=Decision.BLOCK,
    )
    rule2 = DeclarativeRuleModel(
        rule_id="RULE-B",
        description="Rule B",
        author="BlueAI",
        purpose="Test",
        target_family="test",
        feature_names=["is_punycode"],
        predicates=[RulePredicateModel(field="is_punycode", operator="eq", value=1)],
        action=Decision.ALLOW,
    )

    conflicts = DeclarativeRuleEngine.find_rule_conflicts([rule1, rule2])
    assert len(conflicts) > 0
    assert any("Contradictory action" in c for c in conflicts)
