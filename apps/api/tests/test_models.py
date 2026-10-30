"""Tests verifying SQLAlchemy 2.x models, persistence, and relationships."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models import (
    CandidateDefenseRecord,
    DetectionOutcomeRecord,
    DeviceRegistration,
    EvaluationRunRecord,
    FeedbackSubmission,
    PolicyReleaseRecord,
    ThreatAnalysisRecord,
    ThreatObservation,
    UpdateDeliveryRecord,
)


@pytest.mark.asyncio
async def test_threat_observation_persistence(test_db_session: AsyncSession) -> None:
    obs = ThreatObservation(
        normalized_target="target-hash-12345678",
        source="browser_extension",
        local_action_taken="warn",
        engine_version="0.1.0",
        policy_version="2026.10.1",
        telemetry_payload={"flag": "homograph_suspected"},
        verification_status="unverified",
    )
    test_db_session.add(obs)
    await test_db_session.commit()

    stmt = select(ThreatObservation).where(ThreatObservation.id == obs.id)
    retrieved = (await test_db_session.execute(stmt)).scalar_one()
    assert retrieved.normalized_target == "target-hash-12345678"
    assert retrieved.verification_status == "unverified"
    assert retrieved.created_at is not None


@pytest.mark.asyncio
async def test_analysis_and_outcomes_relationship(test_db_session: AsyncSession) -> None:
    analysis = ThreatAnalysisRecord(
        normalized_identifier="ident-hash-87654321",
        threat_score=0.85,
        decision="block",
        confidence=0.92,
        provenance="cloud_analysis",
        engine_version="0.1.0",
        policy_version="2026.10.1",
        evidence_payload=[{"category": "reputation", "reason": "Phishing lure detected"}],
    )
    test_db_session.add(analysis)
    await test_db_session.flush()

    outcome = DetectionOutcomeRecord(
        analysis_id=analysis.id,
        client_id="client-device-101",
        client_action_taken="blocked",
        outcome_metadata={"user_prompt_shown": True},
    )
    test_db_session.add(outcome)
    await test_db_session.commit()

    stmt = select(ThreatAnalysisRecord).where(ThreatAnalysisRecord.id == analysis.id)
    retrieved = (await test_db_session.execute(stmt)).scalar_one()
    assert len(retrieved.outcomes) == 1
    assert retrieved.outcomes[0].client_action_taken == "blocked"


@pytest.mark.asyncio
async def test_candidate_defense_and_evaluations(test_db_session: AsyncSession) -> None:
    candidate = CandidateDefenseRecord(
        version="0.3.0-rc1",
        author_agent="BlueAI-v1",
        description="Enhanced Punycode heuristics",
        rule_spec={"ruleset": "idn_v2"},
        status="evaluating",
    )
    test_db_session.add(candidate)
    await test_db_session.flush()

    eval_run = EvaluationRunRecord(
        candidate_defense_id=candidate.id,
        scenario_suite_id="suite-golden-01",
        total_scenarios=100,
        passed_scenarios=99,
        detection_rate=0.99,
        false_positive_rate=0.01,
        regression_count=0,
        resource_overhead_ms=1.1,
        verdict="pass",
        verdict_rationale="Passed all golden benchmarks",
        evaluated_at=datetime.now(UTC),
    )
    test_db_session.add(eval_run)
    await test_db_session.commit()

    stmt = select(CandidateDefenseRecord).where(CandidateDefenseRecord.id == candidate.id)
    res = (await test_db_session.execute(stmt)).scalar_one()
    assert len(res.evaluations) == 1
    assert res.evaluations[0].verdict == "pass"


@pytest.mark.asyncio
async def test_device_registration_and_update_delivery(test_db_session: AsyncSession) -> None:
    device = DeviceRegistration(
        client_id="anonymous-device-uuid-999",
        client_type="mobile_app",
        platform="Android-15",
        engine_version="0.1.0",
        current_policy_version="2026.09.1",
        is_active=True,
    )
    test_db_session.add(device)

    release = PolicyReleaseRecord(
        policy_version="2026.10.1",
        min_client_version="0.1.0",
        rules_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        publisher_key_id="master-key-01",
        signature="simulated_valid_base64_signature_here_32bytes",
        status="published",
        rules_payload={"regex": ["paypal.*"]},
        published_at=datetime.now(UTC),
        expires_at=datetime.now(UTC),
    )
    test_db_session.add(release)
    await test_db_session.flush()

    delivery = UpdateDeliveryRecord(
        device_id=device.id,
        policy_release_id=release.id,
        status="applied",
        acknowledged_at=datetime.now(UTC),
    )
    test_db_session.add(delivery)
    await test_db_session.commit()

    stmt = select(DeviceRegistration).where(DeviceRegistration.id == device.id)
    retrieved_dev = (await test_db_session.execute(stmt)).scalar_one()
    assert len(retrieved_dev.update_deliveries) == 1
    assert retrieved_dev.update_deliveries[0].status == "applied"


@pytest.mark.asyncio
async def test_feedback_submission(test_db_session: AsyncSession) -> None:
    feedback = FeedbackSubmission(
        feedback_type="false_positive",
        normalized_identifier="hash-disputed-resource",
        user_notes="Legitimate business partner login domain",
        triage_status="pending",
    )
    test_db_session.add(feedback)
    await test_db_session.commit()

    stmt = select(FeedbackSubmission).where(FeedbackSubmission.id == feedback.id)
    retrieved = (await test_db_session.execute(stmt)).scalar_one()
    assert retrieved.feedback_type == "false_positive"
    assert retrieved.triage_status == "pending"
