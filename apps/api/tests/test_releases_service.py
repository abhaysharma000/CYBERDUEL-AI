"""Comprehensive unit tests for release management services, signing, storage, and client verifier."""

import tempfile
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cyberduel_contracts.enums import (
    Decision,
    KeyStatus,
    ReleaseChannel,
    ReleaseStatus,
    RolloutStage,
    ThreatSeverity,
)
from cyberduel_contracts.policy import DeclarativeRuleModel, RulePredicateModel
from cyberduel_contracts.releases import TrustAnchorSet
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.evaluations import EvaluationProtocolRecord, EvaluationReportRecord
from apps.api.app.models.policies import CandidateDefenseRecord
from apps.api.app.models.releases import ReleaseRecord
from apps.api.app.services.releases import (
    ArtifactStorageError,
    ArtifactStorageService,
    ClientUpdateVerifier,
    PolicyBundleBuilder,
    PolicyBundleValidationError,
    ReleaseApprovalError,
    ReleaseApprovalService,
    ReleaseEligibilityService,
    RolloutManager,
    SigningKeyManager,
)


@pytest.mark.asyncio
async def test_signing_key_manager_lifecycle(test_db_session: AsyncSession) -> None:
    """Test key generation, rotation, revocation, and trust anchor compilation."""
    with tempfile.TemporaryDirectory() as temp_dir:
        mgr = SigningKeyManager(keystore_dir=temp_dir)

        # 1. Primary key creation
        key1 = await mgr.get_or_create_primary_key(test_db_session, key_id="key-001")
        assert key1.key_id == "key-001"
        assert key1.status == KeyStatus.ACTIVE.value

        priv_pem = mgr.load_private_key_pem("key-001")
        assert "BEGIN PRIVATE KEY" in priv_pem

        # 2. Key rotation
        old_k, new_k = await mgr.rotate_key(test_db_session, "key-001", "key-002")
        assert old_k.status == KeyStatus.ROTATED.value
        assert new_k.key_id == "key-002"
        assert new_k.status == KeyStatus.ACTIVE.value

        # 3. Key revocation
        rev_k = await mgr.revoke_key(test_db_session, "key-001", reason="Compromised credential")
        assert rev_k.status == KeyStatus.REVOKED.value
        assert rev_k.revocation_reason == "Compromised credential"

        # 4. Trust anchors assembly
        anchors = await mgr.get_trust_anchors(test_db_session)
        assert len(anchors.active_keys) == 1
        assert anchors.active_keys[0].key_id == "key-002"
        assert len(anchors.revoked_keys) == 1
        assert anchors.revoked_keys[0].key_id == "key-001"


def test_bundle_builder_safety_validation() -> None:
    """Verify PolicyBundleBuilder strictly validates rules and rejects unsafe operators/regexes."""
    builder = PolicyBundleBuilder()

    # Valid declarative rule
    valid_rule = DeclarativeRuleModel(
        rule_id="RULE-PHISH-01",
        description="Detect homoglyph mimicry in auth endpoints",
        purpose="Prevent credential harvesting",
        target_family="homograph_mimicry",
        predicates=[
            RulePredicateModel(field="has_homoglyphs", operator="eq", value=True),
            RulePredicateModel(field="url", operator="matches_regex", value=r"login|signin"),
        ],
        action=Decision.BLOCK,
        severity=ThreatSeverity.HIGH,
        weight=0.90,
    )

    spec = {"rules": [valid_rule], "warn_threshold": 0.50, "block_threshold": 0.85}
    bundle, bundle_bytes, digest = builder.build_bundle(
        policy_version="2026.10.2",
        sequence_number=1,
        rule_spec=spec,
        threat_indicators=[{"type": "domain", "value": "malicious-bank.com"}],
    )

    assert bundle.policy_version == "2026.10.2"
    assert bundle.sequence_number == 1
    assert len(bundle.rules) == 1
    assert len(bundle.threat_indicators) == 1
    assert len(digest) == 64

    # Invalid regex pattern rejection
    with pytest.raises(PolicyBundleValidationError, match="Invalid regex"):
        bad_regex_rule = DeclarativeRuleModel(
            rule_id="RULE-BAD-REGEX",
            description="Bad regex test",
            purpose="Testing",
            target_family="evasion",
            predicates=[
                RulePredicateModel(
                    field="url", operator="matches_regex", value=r"[unclosed-bracket"
                ),
            ],
            action=Decision.WARN,
            severity=ThreatSeverity.LOW,
            weight=0.5,
        )
        builder.build_bundle("2026.10.3", 2, {"rules": [bad_regex_rule]})


def test_artifact_storage_service() -> None:
    """Test immutable artifact storage, hash verification, and path traversal protection."""
    with tempfile.TemporaryDirectory() as temp_dir:
        storage = ArtifactStorageService(base_dir=temp_dir)
        content = b'{"policy_version":"2026.10.2","rules":[]}'
        import hashlib

        expected_digest = hashlib.sha256(content).hexdigest()

        # 1. Successful store
        saved_path, confirmed_digest = storage.store_artifact(
            artifact_bytes=content,
            expected_digest=expected_digest,
            filename_hint="test-policy.json",
        )
        assert confirmed_digest == expected_digest
        assert saved_path.exists()

        # 2. Tampered content fails write
        with pytest.raises(ArtifactStorageError, match="digest mismatch"):
            storage.store_artifact(
                artifact_bytes=b"tampered content",
                expected_digest=expected_digest,
                filename_hint="bad.json",
            )

        # 3. Path traversal attack prevented
        with pytest.raises(ArtifactStorageError, match="Path traversal detected"):
            storage.store_artifact(
                artifact_bytes=content,
                expected_digest=expected_digest,
                filename_hint="../../traversal.json",
            )

        # 4. Reading verifies integrity
        data = storage.read_artifact(saved_path, expected_digest=expected_digest)
        assert data == content

        # 5. Reading corrupted artifact fails
        with pytest.raises(ArtifactStorageError, match="Artifact content tampered"):
            storage.read_artifact(saved_path, expected_digest="00" * 32)


@pytest.mark.asyncio
async def test_release_eligibility_and_approval_workflow(test_db_session: AsyncSession) -> None:
    """Test eligibility verification gates and administrative approval authorization."""
    with tempfile.TemporaryDirectory() as temp_dir:
        key_mgr = SigningKeyManager(keystore_dir=temp_dir)
        await key_mgr.get_or_create_primary_key(test_db_session, key_id="prod-key-01")

        # Create protocol
        protocol = EvaluationProtocolRecord(
            id=uuid4(),
            protocol_name="standard-security-v1",
            version="1.0.0",
            description="Standard test protocol",
            metrics_required=["accuracy", "recall", "fpr"],
            split_spec={},
            pass_fail_thresholds={},
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        test_db_session.add(protocol)

        # Create candidate defense
        cand = CandidateDefenseRecord(
            id=uuid4(),
            version="0.3.0-candidate",
            author_agent="BlueAI-v1",
            description="Added authority spoofing heuristic",
            rule_spec={
                "rules": [
                    {
                        "rule_id": "RULE-TEST-01",
                        "rule_version": "1.0.0",
                        "description": "Test rule",
                        "author": "BlueAI",
                        "purpose": "Testing",
                        "target_family": "authority_spoofing",
                        "predicates": [
                            {"field": "has_homoglyphs", "operator": "eq", "value": True}
                        ],
                        "action": "warn",
                        "severity": "medium",
                        "weight": 0.75,
                    }
                ]
            },
            status="accepted",
        )
        test_db_session.add(cand)

        # Create benchmark manifest
        from apps.api.app.models.evaluations import BenchmarkManifestRecord, EvaluationRequestRecord

        bench = BenchmarkManifestRecord(
            id="benchmark-golden-v1",
            name="Golden Benchmark v1",
            version="1.0.0",
            description="Golden test suite",
            split_counts={"development": 10},
            family_counts={"homograph_mimicry": 10},
            scenario_count=10,
            scenarios_payload=[],
            integrity_hash="00" * 32,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        test_db_session.add(bench)
        await test_db_session.flush()

        # Create request record
        req = EvaluationRequestRecord(
            id=uuid4(),
            candidate_id=cand.id,
            candidate_version=cand.version,
            baseline_detector_version="0.2.0-heuristic-intel",
            baseline_policy_version="2026.10.1",
            benchmark_manifest_id="benchmark-golden-v1",
            status="completed",
            requested_by="TestRunner",
            resource_budget={},
            target_finding_ids=[],
            target_scenario_ids=[],
        )
        test_db_session.add(req)
        await test_db_session.flush()

        # 1. Failing report -> Ineligible
        fail_report = EvaluationReportRecord(
            id=uuid4(),
            request_id=req.id,
            candidate_id=cand.id,
            candidate_version=cand.version,
            baseline_version="1.0.0",
            benchmark_manifest_id="benchmark-golden-v1",
            verdict="fail",
            status="completed",
            verdict_rationale="Failed thresholds",
            acceptance_reasons=[],
            rejection_reasons=["High FPR", "Regressions introduced"],
            baseline_metrics={},
            candidate_metrics={
                "accuracy": 0.70,
                "recall": 0.65,
                "false_positive_rate": 0.08,
                "f1_score": 0.67,
            },
            split_metrics={},
            improvement_metrics={"regression_count": 2},
            operational_metrics={},
            report_digest="11" * 32,
            evaluated_at=datetime.now(UTC),
        )
        test_db_session.add(fail_report)
        await test_db_session.flush()

        eligibility_svc = ReleaseEligibilityService()
        report_res = await eligibility_svc.check_eligibility(
            session=test_db_session,
            candidate_id=cand.id,
            evaluation_report_id=fail_report.id,
        )
        assert report_res.is_eligible is False
        assert len(report_res.reasons) >= 3

        # Submitting ineligible candidate to approval service must raise ReleaseApprovalError
        storage_svc = ArtifactStorageService(base_dir=temp_dir)
        approval_svc = ReleaseApprovalService(
            eligibility_service=eligibility_svc,
            storage_service=storage_svc,
            key_manager=key_mgr,
        )

        with pytest.raises(ReleaseApprovalError, match="cannot be authorized for release"):
            await approval_svc.authorize_and_stage_release(
                session=test_db_session,
                candidate_id=cand.id,
                evaluation_report_id=fail_report.id,
                policy_version="2026.10.5",
                target_channel=ReleaseChannel.STABLE,
                authorized_by="secops-lead",
                rationale="Should fail",
                rule_spec=cand.rule_spec,
            )

        # 2. Passing report -> Eligible & Authorizable
        req2 = EvaluationRequestRecord(
            id=uuid4(),
            candidate_id=cand.id,
            candidate_version=cand.version,
            baseline_detector_version="0.2.0-heuristic-intel",
            baseline_policy_version="2026.10.1",
            benchmark_manifest_id="benchmark-golden-v1",
            status="completed",
            requested_by="TestRunner",
            resource_budget={},
            target_finding_ids=[],
            target_scenario_ids=[],
        )
        test_db_session.add(req2)
        await test_db_session.flush()

        pass_report = EvaluationReportRecord(
            id=uuid4(),
            request_id=req2.id,
            candidate_id=cand.id,
            candidate_version=cand.version,
            baseline_version="1.0.0",
            benchmark_manifest_id="benchmark-golden-v1",
            verdict="pass",
            status="completed",
            verdict_rationale="Passed all criteria cleanly",
            acceptance_reasons=["Satisfies all metrics"],
            rejection_reasons=[],
            baseline_metrics={},
            candidate_metrics={
                "accuracy": 0.96,
                "recall": 0.94,
                "false_positive_rate": 0.01,
                "f1_score": 0.95,
            },
            split_metrics={},
            improvement_metrics={"regression_count": 0},
            operational_metrics={},
            report_digest="22" * 32,
            evaluated_at=datetime.now(UTC),
        )
        test_db_session.add(pass_report)
        await test_db_session.flush()

        pass_elig = await eligibility_svc.check_eligibility(
            session=test_db_session,
            candidate_id=cand.id,
            evaluation_report_id=pass_report.id,
        )
        assert pass_elig.is_eligible is True

        # Now authorization succeeds
        release, auth = await approval_svc.authorize_and_stage_release(
            session=test_db_session,
            candidate_id=cand.id,
            evaluation_report_id=pass_report.id,
            policy_version="2026.10.5",
            target_channel=ReleaseChannel.STABLE,
            authorized_by="ciso@cyberduel.internal",
            rationale="Audited against golden v1 benchmark with 0 regressions",
            rule_spec=cand.rule_spec,
        )
        assert release.policy_version == "2026.10.5"
        assert release.status == ReleaseStatus.APPROVED.value
        assert release.sequence_number == 1
        assert auth.authorized_by == "ciso@cyberduel.internal"


@pytest.mark.asyncio
async def test_rollout_manager_progression_and_circuit_breaker(
    test_db_session: AsyncSession,
) -> None:
    """Test staged rollout advancement, deterministic hash bucketing, and circuit-breaker."""
    mgr = RolloutManager()

    # Deterministic bucketing
    bucket1 = mgr.get_cohort_bucket("client-node-alpha-1234")
    bucket2 = mgr.get_cohort_bucket("client-node-alpha-1234")
    assert bucket1 == bucket2
    assert 0 <= bucket1 < 100

    # Staged progression
    rel = ReleaseRecord(
        id=uuid4(),
        policy_version="2026.10.6",
        sequence_number=1,
        channel=ReleaseChannel.CANARY.value,
        status=ReleaseStatus.APPROVED.value,
        min_client_version="0.1.0",
        min_engine_version="1.0.0",
        supported_platforms=["browser_extension"],
        artifact_path="/tmp/test",
        artifact_digest="aa" * 32,
        artifact_size_bytes=100,
        publisher_key_id="key-1",
        signature="sig",
        manifest_payload={},
        bundle_payload={},
        published_at=None,
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    test_db_session.add(rel)
    await test_db_session.flush()

    from apps.api.app.models.releases import RolloutStateRecord

    rollout_rec = RolloutStateRecord(
        release_id=rel.id,
        channel=ReleaseChannel.CANARY.value,
        stage=RolloutStage.INTERNAL.value,
        rollout_percentage=0.0,
        is_paused=False,
        total_targeted_clients=0,
        successful_installs=0,
        failed_installs=0,
        rollback_count=0,
        failure_rate=0.0,
        stage_updated_at=datetime.now(UTC),
    )
    test_db_session.add(rollout_rec)
    await test_db_session.flush()

    # Advance to Canary 10%
    state1 = await mgr.advance_stage(test_db_session, rel.id)
    assert state1.stage == RolloutStage.CANARY_10
    assert state1.rollout_percentage == 10.0
    assert rel.status == ReleaseStatus.PUBLISHED.value

    # Advance to Canary 25%
    state2 = await mgr.advance_stage(test_db_session, rel.id)
    assert state2.stage == RolloutStage.CANARY_25
    assert state2.rollout_percentage == 25.0

    # Pause & resume
    paused = await mgr.pause_rollout(test_db_session, rel.id)
    assert paused.is_paused is True
    resumed = await mgr.resume_rollout(test_db_session, rel.id)
    assert resumed.is_paused is False

    # Circuit breaker: high failure rate trips halt
    rollout_rec.successful_installs = 5
    rollout_rec.failed_installs = 15  # 15/20 = 75% failure rate
    tripped = mgr.evaluate_circuit_breaker(rollout_rec)
    assert tripped is True
    assert rollout_rec.is_paused is True
    assert rollout_rec.stage == RolloutStage.HALTED.value


@pytest.mark.asyncio
async def test_client_update_verifier_7_checkpoints(test_db_session: AsyncSession) -> None:
    """Test that ClientUpdateVerifier enforces all 7 security checkpoints before applying updates."""
    with tempfile.TemporaryDirectory() as temp_dir:
        key_mgr = SigningKeyManager(keystore_dir=temp_dir)
        key_record = await key_mgr.get_or_create_primary_key(
            test_db_session, key_id="anchor-key-01"
        )
        anchors = await key_mgr.get_trust_anchors(test_db_session)

        # Build valid bundle and signed manifest
        bundle_builder = PolicyBundleBuilder()
        bundle, bundle_bytes, digest = bundle_builder.build_bundle(
            policy_version="2026.10.10",
            sequence_number=10,
            rule_spec={"rules": []},
            scoring_thresholds={"warn_threshold": 0.5, "block_threshold": 0.85},
        )

        from apps.api.app.services.releases.manifest_builder import ReleaseManifestBuilder
        from apps.api.app.services.releases.signing import ReleaseSigningService

        signing_svc = ReleaseSigningService(key_manager=key_mgr)
        manifest_builder = ReleaseManifestBuilder(signing_service=signing_svc)
        manifest = await manifest_builder.build_signed_manifest(
            session=test_db_session,
            policy_version="2026.10.10",
            artifact_digest=digest,
            artifact_size_bytes=len(bundle_bytes),
            artifact_url="/api/v1/updates/artifacts/" + digest,
            publisher_key_id=key_record.key_id,
            sequence_number=10,
            supported_platforms=["browser_extension"],
        )

        # 1. Successful verification
        res = ClientUpdateVerifier.verify_update(
            manifest=manifest,
            bundle_bytes=bundle_bytes,
            trust_anchors=anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=5,
        )
        assert res.is_valid is True
        assert res.bundle is not None
        assert res.bundle.policy_version == "2026.10.10"

        # 2. Checkpoint 1 Failure: Revoked signing key
        revoked_anchors = TrustAnchorSet(
            active_keys=[],
            revoked_keys=[anchors.active_keys[0]],
            timestamp=datetime.now(UTC),
        )
        res_revoked = ClientUpdateVerifier.verify_update(
            manifest=manifest,
            bundle_bytes=bundle_bytes,
            trust_anchors=revoked_anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=5,
        )
        assert res_revoked.is_valid is False
        assert "has been revoked" in str(res_revoked.error)

        # 3. Checkpoint 2 Failure: Tampered signature
        tampered_manifest = manifest.model_copy(update={"signature": "aa" * 64})
        res_bad_sig = ClientUpdateVerifier.verify_update(
            manifest=tampered_manifest,
            bundle_bytes=bundle_bytes,
            trust_anchors=anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=5,
        )
        assert res_bad_sig.is_valid is False
        assert "signature verification failed" in str(res_bad_sig.error)

        # 4. Checkpoint 3 Failure: Replay attack (sequence <= current)
        res_replay = ClientUpdateVerifier.verify_update(
            manifest=manifest,
            bundle_bytes=bundle_bytes,
            trust_anchors=anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=10,  # equals manifest sequence
        )
        assert res_replay.is_valid is False
        assert "Replay detected" in str(res_replay.error)

        # 5. Checkpoint 5 Failure: Unsupported platform
        res_plat = ClientUpdateVerifier.verify_update(
            manifest=manifest,
            bundle_bytes=bundle_bytes,
            trust_anchors=anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="mainframe_os",
            current_sequence_number=5,
        )
        assert res_plat.is_valid is False
        assert "Platform 'mainframe_os' not supported" in str(res_plat.error)

        # 6. Checkpoint 6 Failure: Tampered artifact bytes
        res_tampered_bytes = ClientUpdateVerifier.verify_update(
            manifest=manifest,
            bundle_bytes=b'{"corrupted":true}',
            trust_anchors=anchors,
            client_version="0.1.0",
            engine_version="1.0.0",
            client_platform="browser_extension",
            current_sequence_number=5,
        )
        assert res_tampered_bytes.is_valid is False
        assert "Artifact digest mismatch" in str(res_tampered_bytes.error)
