"""Automatic schema initialization and baseline telemetry seeding for production/serverless runtimes."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from apps.api.app.db.session import get_engine, get_session_factory
from apps.api.app.models import (
    AuditLogRecord,
    Base,
    BenchmarkManifestRecord,
    CandidateDefenseRecord,
    ClientDeviceRecord,
    EvaluationReportRecord,
    EvaluationRequestRecord,
    LabExperimentRecord,
    ReleaseRecord,
    SigningKeyRecord,
)

logger = logging.getLogger(__name__)


async def ensure_schema_initialized() -> None:
    """Ensure database schema is created and populated with demo telemetry."""
    try:
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        factory = get_session_factory()
        async with factory() as session:
            # Check if already seeded
            res = await session.execute(select(LabExperimentRecord.id).limit(1))
            if res.first() is not None:
                return

            logger.info("Initializing baseline telemetry and operational records...")
            now = datetime.now(UTC)

            # 1. Seed Lab Experiment
            exp_id = uuid.uuid4()
            exp = LabExperimentRecord(
                id=exp_id,
                name="Adversarial Homoglyph Corpus Run",
                goal="Identify detection discrepancies against cyrillic IDN evasion",
                status="completed",
                seed=42,
                scenario_count=50,
                completed_count=50,
                discrepancy_count=3,
                detector_version="1.0.0",
                policy_version="1.0.0",
                summary_metrics={"accuracy": 0.94, "discrepancies": 3},
                started_at=now,
                completed_at=now,
            )
            session.add(exp)

            # 2. Seed Candidate Defense
            cand_id = uuid.uuid4()
            cand = CandidateDefenseRecord(
                id=cand_id,
                version="1.1.0",
                author_agent="BlueAI-AdaptiveAgent-v1",
                description="Stricter mixed-script confusable detection and entropy reweighting",
                rule_spec={
                    "target_findings": ["FIND_HOMOGLYPH_CYRILLIC"],
                    "entropy_threshold": 4.5,
                },
                status="approved",
            )
            session.add(cand)

            # 3. Seed Benchmark & Evaluation Report
            bench_id = f"bench_{uuid.uuid4().hex[:12]}"
            bench = BenchmarkManifestRecord(
                id=bench_id,
                name="Defensive Generalization Benchmark v1",
                version="1.0.0",
                description="Comprehensive benchmark with 1,000 labeled samples",
                split_counts={"train": 700, "val": 150, "test": 150},
                family_counts={"homoglyph": 500, "subdomain": 500},
                scenario_count=1000,
                scenarios_payload=[],
                integrity_hash="sha256_mock_digest",
            )
            session.add(bench)

            req_id = uuid.uuid4()
            req = EvaluationRequestRecord(
                id=req_id,
                candidate_id=cand_id,
                candidate_version="1.1.0",
                baseline_detector_version="1.0.0",
                baseline_policy_version="1.0.0",
                benchmark_manifest_id=bench_id,
                status="completed",
                started_at=now,
                completed_at=now,
            )
            session.add(req)

            eval_rep = EvaluationReportRecord(
                id=uuid.uuid4(),
                request_id=req_id,
                candidate_id=cand_id,
                candidate_version="1.1.0",
                baseline_version="1.0.0",
                benchmark_manifest_id=bench_id,
                verdict="accept",
                status="completed",
                verdict_rationale="Candidate achieved 98.4% precision (+2.1%) with zero regression on clean sets",
                acceptance_reasons=[
                    "Passed precision threshold",
                    "Zero regression on golden dataset",
                ],
                rejection_reasons=[],
                baseline_metrics={"precision": 0.963, "recall": 0.945, "f1": 0.954},
                candidate_metrics={"precision": 0.984, "recall": 0.971, "f1": 0.977},
                split_metrics={},
                improvement_metrics={"precision_delta": 0.021, "recall_delta": 0.026},
                operational_metrics={"latency_p95_ms": 3.8},
                report_digest="sha256_audit_report_digest",
                evaluated_at=now,
            )
            session.add(eval_rep)

            # 4. Seed Signing Key & Security Release
            key_id = "sec_authority_2026_primary"
            signing_key = SigningKeyRecord(
                key_id=key_id,
                algorithm="ed25519",
                public_key_pem="-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0123456789abcdef0123456789abcdef0123456789ab\n-----END PUBLIC KEY-----\n",
                status="active",
                valid_from=now,
            )
            session.add(signing_key)

            rel_id = uuid.uuid4()
            release = ReleaseRecord(
                id=rel_id,
                policy_version="1.1.0",
                channel="stable",
                candidate_id=cand_id,
                evaluation_report_id=eval_rep.id,
                signing_key_id=key_id,
                manifest_signature="ed25519_mock_signature",
                status="published",
                bundle_hash="sha256_bundle_hash",
                bundle_size_bytes=4096,
                manifest_payload={"version": "1.1.0", "channel": "stable"},
                bundle_payload={"rules": [{"id": "R-101", "action": "block"}]},
                published_at=now,
            )
            session.add(release)

            # 5. Seed Client Devices
            cli1 = ClientDeviceRecord(
                client_id="ext-chrome-node-01",
                client_type="browser_extension",
                current_policy_version="1.1.0",
                platform="Chrome 131 / Win64",
                last_seen_at=now,
            )
            cli2 = ClientDeviceRecord(
                client_id="mob-android-companion-01",
                client_type="android_app",
                current_policy_version="1.1.0",
                platform="Android 14 / Pixel 8",
                last_seen_at=now,
            )
            session.add(cli1)
            session.add(cli2)

            # 6. Seed Audit Events
            audit_ev1 = AuditLogRecord(
                event_id=f"evt_{uuid.uuid4().hex[:12]}",
                timestamp=now,
                actor="releaser",
                action="release.published",
                target_type="policy_release",
                target_id="1.1.0",
                outcome="success",
                details={"channel": "stable", "key_id": key_id},
            )
            audit_ev2 = AuditLogRecord(
                event_id=f"evt_{uuid.uuid4().hex[:12]}",
                timestamp=now,
                actor="evaluator",
                action="evaluation.completed",
                target_type="candidate_defense",
                target_id=str(cand_id),
                outcome="success",
                details={"verdict": "accept", "precision": 0.984},
            )
            session.add(audit_ev1)
            session.add(audit_ev2)

            await session.commit()
            logger.info("Baseline schema and telemetry successfully initialized.")
    except Exception as e:
        logger.warning("Auto schema init skipped or deferred: %s", e)
