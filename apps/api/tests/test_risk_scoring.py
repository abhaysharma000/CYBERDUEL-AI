"""Tests for risk scoring engine, decision boundaries, and fail-safe mechanics."""

from cyberduel_contracts.analysis import EvidenceItem
from cyberduel_contracts.enums import Decision, ThreatSeverity
from cyberduel_threat_intel.scoring import RiskScoringEngine, ScoringPolicyConfig


def test_verified_malicious_indicator_produces_block() -> None:
    engine = RiskScoringEngine()
    indicators = [
        {
            "indicator_type": "url",
            "normalized_value": "https://malicious-test.com/phish",
            "classification": "phishing",
            "verification_status": "verified",
            "confidence": 0.99,
        }
    ]
    outcome = engine.evaluate(indicator_matches=indicators, heuristic_evidence=[])
    assert outcome.decision == Decision.BLOCK
    assert outcome.threat_score >= 0.90
    assert outcome.confidence == 0.98


def test_whitelisted_domain_produces_allow() -> None:
    engine = RiskScoringEngine()
    outcome = engine.evaluate(
        indicator_matches=[],
        heuristic_evidence=[],
        is_whitelisted=True,
    )
    assert outcome.decision == Decision.ALLOW
    assert outcome.threat_score <= 0.05
    assert outcome.confidence == 0.99


def test_suspicious_heuristics_produce_warn_or_block() -> None:
    engine = RiskScoringEngine()
    evidence = [
        EvidenceItem(
            category="homograph",
            reason="Punycode encoding",
            severity=ThreatSeverity.HIGH,
        ),
        EvidenceItem(
            category="lexical",
            reason="Phish keywords present",
            severity=ThreatSeverity.MEDIUM,
        ),
    ]
    outcome = engine.evaluate(indicator_matches=[], heuristic_evidence=evidence)
    assert outcome.decision in {Decision.WARN, Decision.BLOCK}
    assert 0.35 <= outcome.threat_score <= 1.0


def test_score_saturation_bounds() -> None:
    engine = RiskScoringEngine()
    # Multiple high-severity items
    evidence = [
        EvidenceItem(category=f"cat_{i}", reason="test", severity=ThreatSeverity.CRITICAL)
        for i in range(10)
    ]
    outcome = engine.evaluate(indicator_matches=[], heuristic_evidence=evidence)
    # Must remain strictly <= 1.0
    assert 0.0 <= outcome.threat_score <= 1.0
    assert outcome.decision == Decision.BLOCK


def test_fail_safe_behavior() -> None:
    custom_cfg = ScoringPolicyConfig(fail_safe_decision=Decision.WARN, fail_safe_score=0.55)
    engine = RiskScoringEngine(config=custom_cfg)
    outcome = engine.apply_fail_safe("Downstream intelligence service timeout")
    assert outcome.decision == Decision.WARN
    assert outcome.threat_score == 0.55
    assert outcome.fail_safe_applied is True
    assert outcome.confidence is None
