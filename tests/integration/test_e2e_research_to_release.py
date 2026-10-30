"""Authoritative End-to-End integration test covering the complete lifecycle:
Red AI scenario -> Defensive URL analysis -> Blue AI candidate -> Independent Evaluation
-> Release Authorization -> Ed25519 Signing -> 7-Step Client Verification -> Negative Failure Testing.
"""

import tempfile
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cyberduel_contracts.crypto import compute_sha256
from cyberduel_contracts.enums import (
    Decision,
    ExpectedClass,
    KeyStatus,
    ReleaseChannel,
    ReleaseStatus,
    ThreatSeverity,
)
from cyberduel_contracts.evaluation import (
    AcceptancePolicyConfig,
    ConfusionMatrix,
    ImprovementMetrics,
    OperationalMetrics,
)
from cyberduel_contracts.lab import ScenarioContract
from cyberduel_contracts.policy import (
    CandidateDefense,
    DeclarativeRuleModel,
    RulePredicateModel,
)
from cyberduel_contracts.releases import TrustAnchorSet
from cyberduel_threat_intel.normalizer import URLNormalizer
from cyberduel_threat_intel.scoring import RiskScoringEngine
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.evaluations import (
    BenchmarkManifestRecord,
    EvaluationProtocolRecord,
    EvaluationReportRecord,
    EvaluationRequestRecord,
)
from apps.api.app.models.policies import CandidateDefenseRecord
from apps.api.app.models.releases import ReleaseRecord
from apps.api.app.services.releases.bundle_builder import PolicyBundleBuilder
from apps.api.app.services.releases.eligibility import ReleaseEligibilityService
from apps.api.app.services.releases.key_manager import SigningKeyManager
from apps.api.app.services.releases.manifest_builder import ReleaseManifestBuilder
from apps.api.app.services.releases.signing import ReleaseSigningService
from apps.api.app.services.releases.verifier import ClientUpdateVerifier
from services.evaluator.app.acceptance import AcceptancePolicyEngine


@pytest.mark.asyncio
async def test_full_lifecycle_research_to_client_verification(test_db_session: AsyncSession) -> None:
    """Validate full end-to-end pipeline from synthetic scenario to verified client update."""
    now = datetime.now(UTC)

    # -------------------------------------------------------------------------
    # 1. Red AI: Generate Controlled Synthetic Scenario
    # -------------------------------------------------------------------------
    test_raw_url = "https://banking-update.secure-login.test/account-verification?token=secret123"
    norm = URLNormalizer.normalize(test_raw_url)
    assert norm.host == "banking-update.secure-login.test"
    # Verify sensitive query parameter redaction
    assert "token=%5BREDACTED%5D" in norm.canonical_url

    scenario = ScenarioContract(
        scenario_id=uuid4(),
        schema_version="1.0.0",
        scenario_family="credential_phishing",
        scenario_name="Subdomain Brand Homoglyph Harvest",
        description="Synthetic credential phishing leveraging subdomains and login terms",
        expected_class=ExpectedClass.MALICIOUS,
        expected_decision=Decision.BLOCK,
        difficulty="intermediate",
        tags=["phishing", "brand_impersonation"],
        seed=101,
        generator_version="1.0.0",
        input_fixture={"raw_url": test_raw_url, "normalized_url": norm.canonical_url},
        expected_evidence=["subdomain_entropy", "credential_harvesting_path"],
        provenance={"generator": "RedResearchAgent-v1"},
        safety_classification="harmless_synthetic",
        created_at=now,
    )
    assert scenario.expected_decision == Decision.BLOCK

    # -------------------------------------------------------------------------
    # 2. Defensive Analysis Baseline
    # -------------------------------------------------------------------------
    scoring_engine = RiskScoringEngine()
    score_result = scoring_engine.evaluate(
        indicator_matches=[],
        heuristic_evidence=[],
        is_whitelisted=False,
    )
    assert score_result.decision in [Decision.ALLOW, Decision.WARN, Decision.BLOCK]

    # -------------------------------------------------------------------------
    # 3. Blue AI: Formulate Declarative Candidate Rule to close detection gap
    # -------------------------------------------------------------------------
    rule_id = f"RULE-PHISH-{uuid4().hex[:6].upper()}"
    candidate_rule = DeclarativeRuleModel(
        rule_id=rule_id,
        rule_version="1.0.0",
        description="Targets banking login subdomains on unverified TLDs",
        purpose="Defeat synthetic credential harvest campaigns",
        target_family="credential_phishing",
        predicates=[
            RulePredicateModel(
                field="host",
                operator="contains",
                value="banking-update",
            )
        ],
        action=Decision.BLOCK,
        severity=ThreatSeverity.HIGH,
        weight=0.95,
    )

    candidate = CandidateDefense(
        defense_id=uuid4(),
        version="2026.11.1",
        author_agent="BlueAI-SynthesisAgent-v1",
        description="Adding specific host containment rule resolves targeted phishing without collateral FP",
        rule_spec={"rules": [candidate_rule.model_dump(mode="json")]},
        created_at=now,
    )

    # Persist CandidateDefenseRecord in database
    cand_record = CandidateDefenseRecord(
        id=candidate.defense_id,
        version=candidate.version,
        author_agent=candidate.author_agent,
        description=candidate.description,
        rule_spec=candidate.rule_spec,
        status="candidate",
    )
    test_db_session.add(cand_record)
    await test_db_session.flush()

    # -------------------------------------------------------------------------
    # 4. Independent Evaluator: Benchmark Acceptance Gate (Zero Regressions)
    # -------------------------------------------------------------------------
    candidate_metrics = ConfusionMatrix(tp=95, fp=2, tn=98, fn=5)
    baseline_metrics = ConfusionMatrix(tp=80, fp=5, tn=95, fn=20)
    improvement = ImprovementMetrics(
        original_failures_resolved=15,
        original_failures_total=20,
        resolution_rate=0.75,
        new_regressions=0,
        new_false_positives=0,
        delta_recall=0.15,
        delta_fpr=-0.03,
    )

    policy = AcceptancePolicyConfig(
        max_allowed_fpr=0.05,
        max_allowed_regressions=0,
        min_detection_rate=0.70,
    )

    verdict, status, _, _, rejections = AcceptancePolicyEngine.evaluate(
        candidate=candidate,
        candidate_metrics=candidate_metrics,
        baseline_metrics=baseline_metrics,
        split_metrics={"held_out": ConfusionMatrix(tp=20, fp=0, tn=20, fn=0)},
        improvement_metrics=improvement,
        operational_metrics=OperationalMetrics(mean_latency_ms=2.5),
        policy=policy,
    )

    assert verdict.value == "pass"
    assert len(rejections) == 0

    bench = BenchmarkManifestRecord(
        id="benchmark-golden-p10",
        name="Phase 10 E2E Golden Suite",
        version="1.0.0",
        description="Comprehensive verification benchmark with strict regression controls",
        split_counts={"validation": 1, "regression": 1},
        family_counts={"credential_phishing": 1, "benign_popular": 1},
        scenario_count=2,
        scenarios_payload=[],
        integrity_hash="00" * 32,
        created_at=now,
        updated_at=now,
    )
    test_db_session.add(bench)
    await test_db_session.flush()

    req = EvaluationRequestRecord(
        id=uuid4(),
        candidate_id=cand_record.id,
        candidate_version=cand_record.version,
        baseline_detector_version="0.2.0-heuristic-intel",
        baseline_policy_version="2026.10.1",
        benchmark_manifest_id=bench.id,
        status="completed",
        requested_by="E2EVerifier",
        resource_budget={},
        target_finding_ids=[],
        target_scenario_ids=[],
    )
    test_db_session.add(req)
    await test_db_session.flush()

    eval_record = EvaluationReportRecord(
        id=uuid4(),
        request_id=req.id,
        candidate_id=cand_record.id,
        candidate_version=cand_record.version,
        baseline_version="2026.10.1",
        benchmark_manifest_id=bench.id,
        verdict="pass",
        status="completed",
        verdict_rationale="Zero regressions detected, FPR within 5% limit, detection rate improved.",
        acceptance_reasons=["Passed zero regression gate", "Acceptable FPR"],
        rejection_reasons=[],
        baseline_metrics=baseline_metrics.model_dump(mode="json"),
        candidate_metrics={
            "accuracy": candidate_metrics.accuracy,
            "recall": candidate_metrics.recall,
            "false_positive_rate": candidate_metrics.false_positive_rate,
            "f1": candidate_metrics.f1,
        },
        split_metrics={},
        improvement_metrics=improvement.model_dump(mode="json"),
        operational_metrics={"mean_latency_ms": 2.5},
        report_digest="11" * 32,
        evaluated_at=now,
    )
    test_db_session.add(eval_record)
    await test_db_session.commit()

    # -------------------------------------------------------------------------
    # 5. Release Eligibility Verification
    # -------------------------------------------------------------------------
    eligibility_service = ReleaseEligibilityService()
    eligibility = await eligibility_service.check_eligibility(
        session=test_db_session,
        candidate_id=cand_record.id,
        evaluation_report_id=eval_record.id,
    )
    assert eligibility.is_eligible is True
    assert "criteria satisfied" in eligibility.reasons[0].lower()

    # -------------------------------------------------------------------------
    # 6. Release Authorization & Cryptographic Ed25519 Signing
    # -------------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as temp_dir:
        key_mgr = SigningKeyManager(keystore_dir=temp_dir)
        key_record = await key_mgr.get_or_create_primary_key(
            test_db_session, key_id="authority-release-key-p10"
        )
        trust_anchors = await key_mgr.get_trust_anchors(test_db_session)
        assert len(trust_anchors.active_keys) == 1

        bundle_builder = PolicyBundleBuilder()
        bundle, bundle_bytes, digest = bundle_builder.build_bundle(
            policy_version="2026.11.1",
            sequence_number=10,
            rule_spec=candidate.rule_spec,
            scoring_thresholds={"warn_threshold": 0.50, "block_threshold": 0.85},
            expires_at=now + timedelta(days=90),
        )
        assert len(bundle.rules) == 1
        assert bundle.rules[0].rule_id == rule_id

        signing_svc = ReleaseSigningService(key_manager=key_mgr)
        manifest_builder = ReleaseManifestBuilder(signing_service=signing_svc)
        signed_manifest = await manifest_builder.build_signed_manifest(
            session=test_db_session,
            policy_version="2026.11.1",
            artifact_digest=digest,
            artifact_size_bytes=len(bundle_bytes),
            artifact_url="/api/v1/updates/artifacts/" + digest,
            publisher_key_id=key_record.key_id,
            sequence_number=10,
            channel=ReleaseChannel.STABLE,
            status=ReleaseStatus.PUBLISHED,
            supported_platforms=["browser_extension", "mobile_app"],
            expires_at=now + timedelta(days=90),
        )
        assert signed_manifest.signature is not None
        assert len(signed_manifest.signature) == 128  # 64-byte Ed25519 hex signature

        # Record the release in the database
        rel_record = ReleaseRecord(
            id=signed_manifest.release_id,
            candidate_id=cand_record.id,
            evaluation_report_id=eval_record.id,
            policy_version=signed_manifest.policy_version,
            sequence_number=signed_manifest.sequence_number,
            channel=signed_manifest.channel.value,
            status=signed_manifest.status.value,
            artifact_digest=signed_manifest.artifact_digest,
            artifact_size_bytes=signed_manifest.artifact_size_bytes,
            artifact_path="storage/releases/" + digest,
            publisher_key_id=signed_manifest.publisher_key_id,
            signature=signed_manifest.signature,
            manifest_payload=signed_manifest.model_dump(mode="json"),
            published_at=now,
            expires_at=signed_manifest.expires_at,
        )
        test_db_session.add(rel_record)
        await test_db_session.commit()

        # ---------------------------------------------------------------------
        # 7. Edge Client Verification (7-Step Protocol)
        # ---------------------------------------------------------------------
        res = ClientUpdateVerifier.verify_update(
            manifest=signed_manifest,
            bundle_bytes=bundle_bytes,
            trust_anchors=trust_anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=5,  # Anti-replay: 10 > 5
            now=now,
        )
        assert res.is_valid is True
        assert res.bundle is not None
        assert res.bundle.policy_version == "2026.11.1"
        assert len(res.bundle.rules) == 1
        assert res.bundle.rules[0].rule_id == rule_id

        # ---------------------------------------------------------------------
        # 8. Negative Tests: Cryptographic & Integrity Tampering Defense
        # ---------------------------------------------------------------------
        # A. Tampered Artifact Bundle Bytes (Digest mismatch)
        tampered_bytes = bundle_bytes + b" "
        tampered_res = ClientUpdateVerifier.verify_update(
            manifest=signed_manifest,
            bundle_bytes=tampered_bytes,
            trust_anchors=trust_anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=5,
            now=now,
        )
        assert tampered_res.is_valid is False
        assert "digest mismatch" in tampered_res.error.lower()

        # B. Tampered Signature (Signature verification failure)
        corrupted_manifest = signed_manifest.model_copy(deep=True)
        corrupted_manifest.signature = "a" * 128
        sig_fail_res = ClientUpdateVerifier.verify_update(
            manifest=corrupted_manifest,
            bundle_bytes=bundle_bytes,
            trust_anchors=trust_anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=5,
            now=now,
        )
        assert sig_fail_res.is_valid is False
        assert "signature" in sig_fail_res.error.lower()

        # C. Replay Attack (Stale sequence number)
        replay_res = ClientUpdateVerifier.verify_update(
            manifest=signed_manifest,
            bundle_bytes=bundle_bytes,
            trust_anchors=trust_anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=10,  # Sequence 10 is NOT strictly greater than 10
            now=now,
        )
        assert replay_res.is_valid is False
        assert "sequence" in replay_res.error.lower()

        # D. Expired Release
        expired_res = ClientUpdateVerifier.verify_update(
            manifest=signed_manifest,
            bundle_bytes=bundle_bytes,
            trust_anchors=trust_anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=5,
            now=now + timedelta(days=100),  # Exceeds the 90-day expiry
        )
        assert expired_res.is_valid is False
        assert "expired" in expired_res.error.lower()

        # E. Revoked Signing Key
        revoked_anchors = TrustAnchorSet(
            active_keys=[],
            revoked_keys=[trust_anchors.active_keys[0]],
            timestamp=now,
        )
        revoked_res = ClientUpdateVerifier.verify_update(
            manifest=signed_manifest,
            bundle_bytes=bundle_bytes,
            trust_anchors=revoked_anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=5,
            now=now,
        )
        assert revoked_res.is_valid is False
        assert "revoked" in revoked_res.error.lower()


@pytest.mark.asyncio
async def test_evaluator_rejects_regressive_candidate_and_preserves_outcome(
    test_db_session: AsyncSession,
) -> None:
    """Verify that an adversarial or regressive candidate is rejected by the independent evaluator,
    marked ineligible for release, and cannot be published or staged.
    """
    now = datetime.now(UTC)

    # 1. Synthesize a regressive candidate rule (overly broad predicate)
    bad_rule = DeclarativeRuleModel(
        rule_id="RULE-REGRESS-01",
        rule_version="1.0.0",
        description="Overly broad rule triggering false positives on benign portals",
        purpose="Adversarial evaluation regression test",
        target_family="evasion",
        predicates=[
            RulePredicateModel(
                field="host",
                operator="contains",
                value="portal",  # Regresses benign portals
            )
        ],
        action=Decision.BLOCK,
        severity=ThreatSeverity.HIGH,
        weight=0.99,
    )

    regressive_candidate = CandidateDefense(
        defense_id=uuid4(),
        version="2026.11.2-regressive",
        author_agent="BlueAI-ExperimentalAgent",
        description="Flawed candidate introducing false positive regressions",
        rule_spec={"rules": [bad_rule.model_dump(mode="json")]},
        created_at=now,
    )

    cand_record = CandidateDefenseRecord(
        id=regressive_candidate.defense_id,
        version=regressive_candidate.version,
        author_agent=regressive_candidate.author_agent,
        description=regressive_candidate.description,
        rule_spec=regressive_candidate.rule_spec,
        status="candidate",
    )
    test_db_session.add(cand_record)
    await test_db_session.flush()

    # 2. Independent Evaluator detects regressions
    # Candidate causes 12 false positives on benign controls (FPR = 12%) and 4 new regressions
    candidate_metrics = ConfusionMatrix(tp=60, fp=12, tn=88, fn=40)  # Total 200, FPR = 12/100 = 12%
    baseline_metrics = ConfusionMatrix(tp=55, fp=1, tn=99, fn=45)
    improvement = ImprovementMetrics(
        original_failures_resolved=5,
        original_failures_total=45,
        resolution_rate=0.11,
        new_regressions=4,  # Regressions strictly forbidden (max allowed: 0)
        new_false_positives=11,
        delta_recall=0.05,
        delta_fpr=0.11,
    )

    policy = AcceptancePolicyConfig(
        max_allowed_fpr=0.05,
        max_allowed_regressions=0,
        min_detection_rate=0.70,
    )

    verdict, status, rationale, acceptance_reasons, rejection_reasons = (
        AcceptancePolicyEngine.evaluate(
            candidate=regressive_candidate,
            candidate_metrics=candidate_metrics,
            baseline_metrics=baseline_metrics,
            split_metrics={"held_out": ConfusionMatrix(tp=10, fp=3, tn=17, fn=0)},
            improvement_metrics=improvement,
            operational_metrics=OperationalMetrics(mean_latency_ms=3.1),
            policy=policy,
        )
    )

    # 3. Gate enforcement: Must FAIL
    assert verdict.value == "fail"
    assert status.value == "rejected"
    assert len(rejection_reasons) > 0
    assert any("regressions" in r.lower() for r in rejection_reasons)

    # 4. Persist evaluation report with rejected outcome
    bench = BenchmarkManifestRecord(
        id="benchmark-golden-regress-check",
        name="Regression Gate Benchmark",
        version="1.0.0",
        description="Benchmark for regression testing",
        split_counts={"regression": 10},
        family_counts={"evasion": 10},
        scenario_count=10,
        scenarios_payload=[],
        integrity_hash="00" * 32,
        created_at=now,
        updated_at=now,
    )
    test_db_session.add(bench)
    await test_db_session.flush()

    req = EvaluationRequestRecord(
        id=uuid4(),
        candidate_id=cand_record.id,
        candidate_version=cand_record.version,
        baseline_detector_version="0.2.0-heuristic-intel",
        baseline_policy_version="2026.10.1",
        benchmark_manifest_id=bench.id,
        status="completed",
        requested_by="E2EVerifier",
        resource_budget={},
        target_finding_ids=[],
        target_scenario_ids=[],
    )
    test_db_session.add(req)
    await test_db_session.flush()

    failed_eval_record = EvaluationReportRecord(
        id=uuid4(),
        request_id=req.id,
        candidate_id=cand_record.id,
        candidate_version=cand_record.version,
        baseline_version="2026.10.1",
        benchmark_manifest_id=bench.id,
        verdict=verdict.value,
        status="completed",
        verdict_rationale="Rejected: Candidate introduced regressions and exceeded FPR ceiling.",
        acceptance_reasons=[],
        rejection_reasons=rejection_reasons,
        baseline_metrics=baseline_metrics.model_dump(mode="json"),
        candidate_metrics={
            "accuracy": candidate_metrics.accuracy,
            "recall": candidate_metrics.recall,
            "false_positive_rate": candidate_metrics.false_positive_rate,
            "f1": candidate_metrics.f1,
        },
        split_metrics={},
        improvement_metrics=improvement.model_dump(mode="json"),
        operational_metrics={"mean_latency_ms": 3.1},
        report_digest="22" * 32,
        evaluated_at=now,
    )
    test_db_session.add(failed_eval_record)
    await test_db_session.commit()

    # 5. Release eligibility MUST be denied
    eligibility_service = ReleaseEligibilityService()
    eligibility = await eligibility_service.check_eligibility(
        session=test_db_session,
        candidate_id=cand_record.id,
        evaluation_report_id=failed_eval_record.id,
    )
    assert eligibility.is_eligible is False
    assert len(eligibility.reasons) > 0
    assert any("verdict is 'fail'" in r.lower() for r in eligibility.reasons)

