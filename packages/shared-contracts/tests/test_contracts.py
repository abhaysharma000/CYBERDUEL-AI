"""Tests for canonical shared contracts and Pydantic validation."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cyberduel_contracts import (
    Decision,
    EvaluationResult,
    EvaluationVerdict,
    EvidenceItem,
    PolicyReleaseManifest,
    ProvenanceType,
    ReleaseStatus,
    ResourceAnalysisRequest,
    ThreatAnalysisResult,
    ThreatSeverity,
)
from pydantic import ValidationError


def test_resource_analysis_request_valid() -> None:
    req = ResourceAnalysisRequest(
        normalized_identifier="a" * 64,
        resource_url="https://example.com/login",
        resource_type="url",
        client_id="client-test-123",
    )
    assert req.normalized_identifier == "a" * 64
    assert req.resource_type == "url"


def test_resource_analysis_request_forbids_extra() -> None:
    with pytest.raises(ValidationError):
        ResourceAnalysisRequest(
            normalized_identifier="a" * 64,
            unrecognized_field="malicious_injection",  # type: ignore[call-arg]
        )


def test_threat_analysis_result_valid() -> None:
    evidence = [
        EvidenceItem(
            category="reputation",
            reason="Domain matched known phishing heuristic",
            severity=ThreatSeverity.HIGH,
            confidence=0.95,
        )
    ]
    res = ThreatAnalysisResult(
        normalized_identifier="b" * 64,
        threat_score=0.88,
        decision=Decision.BLOCK,
        evidence=evidence,
        engine_version="0.1.0",
        policy_version="2026.10.1",
        confidence=0.92,
        provenance=ProvenanceType.CLOUD_ANALYSIS,
    )
    assert res.decision == Decision.BLOCK
    assert res.threat_score == 0.88
    assert len(res.evidence) == 1
    assert res.evidence[0].category == "reputation"


def test_threat_analysis_result_rejects_invalid_score() -> None:
    with pytest.raises(ValidationError):
        ThreatAnalysisResult(
            normalized_identifier="b" * 64,
            threat_score=1.5,  # Invalid: must be <= 1.0
            decision=Decision.BLOCK,
            engine_version="0.1.0",
            policy_version="2026.10.1",
            provenance=ProvenanceType.LOCAL_RULE,
        )

    with pytest.raises(ValidationError):
        ThreatAnalysisResult(
            normalized_identifier="b" * 64,
            threat_score=-0.1,  # Invalid: must be >= 0.0
            decision=Decision.ALLOW,
            engine_version="0.1.0",
            policy_version="2026.10.1",
            provenance=ProvenanceType.LOCAL_RULE,
        )


def test_threat_analysis_result_rejects_invalid_decision() -> None:
    with pytest.raises(ValidationError):
        ThreatAnalysisResult(
            normalized_identifier="b" * 64,
            threat_score=0.5,
            decision="unknown_decision",  # type: ignore[arg-type]
            engine_version="0.1.0",
            policy_version="2026.10.1",
            provenance=ProvenanceType.LOCAL_RULE,
        )


def test_evaluation_result_bounds() -> None:
    eval_res = EvaluationResult(
        candidate_defense_id=uuid4(),
        scenario_suite_id="suite-phish-2026",
        total_scenarios=100,
        passed_scenarios=98,
        detection_rate=0.98,
        false_positive_rate=0.01,
        regression_count=0,
        resource_overhead_ms=1.2,
        verdict=EvaluationVerdict.PASS,
        verdict_rationale="Passed all regression and false-positive checks",
    )
    assert eval_res.verdict == EvaluationVerdict.PASS
    assert eval_res.detection_rate == 0.98

    with pytest.raises(ValidationError):
        EvaluationResult(
            candidate_defense_id=uuid4(),
            scenario_suite_id="suite-phish-2026",
            total_scenarios=0,  # Invalid: ge=1
            passed_scenarios=0,
            detection_rate=1.1,  # Invalid: le=1.0
            false_positive_rate=0.0,
            verdict=EvaluationVerdict.FAIL,
            verdict_rationale="Invalid",
        )


def test_policy_release_manifest_digest_format() -> None:
    valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    manifest = PolicyReleaseManifest(
        policy_version="2026.10.1",
        min_client_version="0.1.0",
        rules_digest=valid_sha256,
        publisher_key_id="master-key-1",
        signature="simulated_valid_base64_signature_here_minimum_len",
        expires_at=datetime.now(UTC),
        status=ReleaseStatus.PUBLISHED,
    )
    assert manifest.rules_digest == valid_sha256

    # Test invalid digest string (not 64-char hex)
    with pytest.raises(ValidationError):
        PolicyReleaseManifest(
            policy_version="2026.10.1",
            min_client_version="0.1.0",
            rules_digest="invalid_short_hash",
            publisher_key_id="master-key-1",
            signature="signature",
            expires_at=datetime.now(UTC),
        )
