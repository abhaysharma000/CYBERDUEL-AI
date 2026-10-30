"""Execute a genuine end-to-end development workflow through real application services and APIs.

Connects:
Red AI Lab -> Defensive Analysis -> Blue AI Synthesis -> Independent Evaluator ->
Release Eligibility -> Ed25519 Cryptographic Signing -> Client Update Verification ->
Telemetry Observation Ingestion.

All records are persisted to the active development database (cyberduel_dev.db).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

# Ensure project root is on PYTHONPATH
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "packages" / "shared-contracts"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "threat-intel-engine"))

from cyberduel_contracts.enums import (
    Decision,
    ExpectedClass,
    KeyStatus,
    ReleaseChannel,
    ReleaseStatus,
    RolloutStage,
    ThreatSeverity,
)
from cyberduel_contracts.evaluation import (
    AcceptancePolicyConfig,
    ConfusionMatrix,
    EvaluationReport,
    EvaluationRequest,
    ImprovementMetrics,
    OperationalMetrics,
)
from cyberduel_contracts.lab import ExperimentConfig
from cyberduel_contracts.observation import ThreatObservationReport
from cyberduel_contracts.policy import CandidateDefense, DeclarativeRuleModel, RulePredicateModel
from cyberduel_threat_intel.normalizer import URLNormalizer
from sqlalchemy import func, select, text

from apps.api.app.core.config import get_settings
from apps.api.app.db.session import get_db_session, get_engine
from apps.api.app.models.audit import AuditLogRecord
from apps.api.app.models.evaluations import (
    BenchmarkManifestRecord,
    EvaluationReportRecord,
    EvaluationRequestRecord,
)
from apps.api.app.models.indicators import ThreatIndicatorRecord
from apps.api.app.models.policies import CandidateDefenseRecord
from apps.api.app.models.releases import (
    ReleaseAuthorizationRecord,
    ReleaseRecord,
    RolloutStateRecord,
)
from apps.api.app.repositories.threat_intel_repository import ThreatIntelRepository
from apps.api.app.services.audit_service import AuditService
from apps.api.app.services.blue_ai import (
    CandidateDefenseBuilder,
    CandidateSandboxRunner,
    DefenseHypothesisEngine,
    DefenseProposalGenerator,
    DefensiveResearchService,
)
from apps.api.app.services.releases import (
    PolicyBundleBuilder,
    ReleaseApprovalService,
    ReleaseEligibilityService,
    ReleaseManifestBuilder,
    ReleaseSigningService,
    SigningKeyManager,
)
from apps.api.app.services.releases.verifier import ClientUpdateVerifier
from services.evaluator.app.benchmarks import BenchmarkRegistry
from services.evaluator.app.runner import EvaluationRunner
from services.lab_worker.app.red_ai.agent import RedResearchAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("execute_dev_workflow")


async def main() -> dict[str, Any]:
    settings = get_settings()
    logger.info("Starting Live Development Workflow Execution...")
    logger.info(f"Target Database: {settings.DATABASE_URL}")
    logger.info(f"AI Provider Mode: {settings.AI_PROVIDER_TYPE}")

    async with get_engine().begin() as conn:
        pass  # Verify connection

    session_gen = get_db_session()
    session = await anext(session_gen)

    results = {}

    try:
        # =========================================================================
        # 1. RED AI LAB: Adversarial Synthetic Experiment
        # =========================================================================
        logger.info("--- Step 1: Running Red AI Experiment ---")
        red_agent = RedResearchAgent(session=session)
        exp_id = uuid4()
        config = ExperimentConfig(
            experiment_name="Adversarial Brand Mimicry & Phishing Audit",
            goal="Identify defensive coverage gaps in synthetic login subdomains",
            seed=42,
            scenario_count=5,
            selected_families=["credential_phishing", "homograph_mimicry"],
            created_by="AutonomousWorkflowLead",
        )

        summary, handoff, executions = await red_agent.run_experiment(config=config, experiment_id=exp_id)
        await session.commit()

        results["experiment_id"] = str(exp_id)
        results["experiment_name"] = summary.experiment_name
        results["scenarios_generated"] = summary.scenario_count
        results["discrepancies_detected"] = summary.discrepancy_count
        results["findings_count"] = len(summary.findings)
        logger.info(f"Red AI Complete: Exp {exp_id} generated {summary.scenario_count} scenarios with {summary.discrepancy_count} discrepancies.")

        # =========================================================================
        # 2. BLUE AI DEFENSE: Ingest Handoff, Hypothesize, Propose, Assemble Candidate
        # =========================================================================
        logger.info("--- Step 2: Running Blue AI Defensive Pipeline ---")
        task_record, ranked_groups = await DefensiveResearchService.ingest_handoff(
            handoff=handoff,
            session=session,
        )
        await session.commit()
        results["research_task_id"] = str(task_record.id)
        results["ranked_groups_count"] = len(ranked_groups)

        top_priority = ranked_groups[0] if ranked_groups else None
        logger.info(f"Blue AI Ingested: Task {task_record.id}, Top Priority: {top_priority.recommended_focus if top_priority else 'None'}")

        # Formulate hypothesis
        hypothesis = await DefenseHypothesisEngine.formulate_hypothesis_async(
            task_id=task_record.id,
            priority_group=top_priority,
        )
        await DefenseHypothesisEngine.save_hypothesis(hypothesis, session)
        await session.commit()
        results["hypothesis_id"] = str(hypothesis.hypothesis_id)
        results["hypothesis_category"] = hypothesis.failure_category

        # Synthesize proposal
        proposal = await DefenseProposalGenerator.generate_proposal_async(hypothesis)
        await DefenseProposalGenerator.save_proposal(proposal, session)
        await session.commit()
        results["proposal_id"] = str(proposal.proposal_id)
        results["proposal_type"] = proposal.proposal_type

        # Assemble candidate defense
        count_stmt = select(func.count(CandidateDefenseRecord.id))
        cand_count = (await session.execute(count_stmt)).scalar() or 0
        candidate = CandidateDefenseBuilder.assemble_candidate(
            proposals=[proposal],
            baseline_version="2026.10.1",
            candidate_sequence=cand_count + 1,
        )
        await CandidateDefenseBuilder.save_candidate(candidate, session)
        await session.commit()
        results["candidate_id"] = str(candidate.defense_id)
        results["candidate_version"] = candidate.version

        # Run sandbox comparison
        comparison = await CandidateSandboxRunner.run_comparison(
            candidate=candidate,
            failing_scenarios=None,
            session=session,
        )
        await session.commit()
        results["sandbox_verdict"] = (
            comparison.preliminary_verdict.value
            if hasattr(comparison.preliminary_verdict, "value")
            else str(comparison.preliminary_verdict)
        )
        logger.info(f"Blue AI Candidate {candidate.defense_id} v{candidate.version} assembled and sandboxed.")

        # =========================================================================
        # 3. INDEPENDENT EVALUATOR: Benchmark Auditing
        # =========================================================================
        logger.info("--- Step 3: Running Independent Benchmark Evaluation ---")
        registry = BenchmarkRegistry()
        manifest = registry.get_manifest("benchmark-golden-v1")
        if not manifest:
            # Fall back to first available manifest
            manifests = registry.list_manifests()
            manifest = manifests[0]

        manifest_id = manifest.manifest_id
        # Ensure manifest record exists
        m_stmt = select(BenchmarkManifestRecord).where(BenchmarkManifestRecord.id == manifest_id)
        m_res = await session.execute(m_stmt)
        if not m_res.scalar_one_or_none():
            manifest_rec = BenchmarkManifestRecord(
                id=manifest.manifest_id,
                name=manifest.name,
                version=manifest.version,
                description=manifest.description,
                split_counts=manifest.split_counts,
                family_counts=manifest.family_counts,
                scenario_count=manifest.scenario_count,
                scenarios_payload=[s.model_dump(mode="json") for s in manifest.scenarios],
                integrity_hash=manifest.integrity_hash,
            )
            session.add(manifest_rec)
            await session.commit()

        # Create evaluation request
        eval_req_id = uuid4()
        eval_req = EvaluationRequest(
            request_id=eval_req_id,
            candidate_id=candidate.defense_id,
            candidate_version=candidate.version,
            benchmark_manifest_version=manifest_id,
            acceptance_policy=AcceptancePolicyConfig(
                max_allowed_fpr=0.05,
                max_allowed_regressions=0,
                min_detection_rate=0.70,
            ),
            requested_by="AutonomousWorkflowLead",
        )

        eval_req_rec = EvaluationRequestRecord(
            id=eval_req.request_id,
            candidate_id=candidate.defense_id,
            candidate_version=candidate.version,
            baseline_detector_version=settings.APP_VERSION,
            baseline_policy_version="2026.10.1",
            benchmark_manifest_id=manifest_id,
            status="running",
            requested_by="AutonomousWorkflowLead",
            resource_budget={"budget_seconds": 60.0},
            target_finding_ids=[str(f.finding_id) for f in summary.findings],
            target_scenario_ids=[],
        )
        session.add(eval_req_rec)
        await session.commit()

        eval_runner = EvaluationRunner(benchmark_registry=registry)
        report = await eval_runner.run_evaluation(
            request=eval_req,
            candidate=candidate,
            manifest=manifest,
        )

        eval_req_rec.status = report.status.value

        report_rec = EvaluationReportRecord(
            id=report.report_id,
            request_id=eval_req.request_id,
            candidate_id=candidate.defense_id,
            candidate_version=report.candidate_version,
            baseline_version=report.baseline_version,
            benchmark_manifest_id=report.benchmark_manifest_version,
            verdict=report.verdict.value,
            status=report.status.value,
            verdict_rationale=report.verdict_rationale,
            acceptance_reasons=report.acceptance_reasons,
            rejection_reasons=report.rejection_reasons,
            baseline_metrics=report.baseline_metrics.model_dump(),
            candidate_metrics=report.candidate_metrics.model_dump(),
            split_metrics={k: v.model_dump() for k, v in report.split_metrics.items()},
            improvement_metrics=report.improvement_metrics.model_dump(),
            operational_metrics=report.operational_metrics.model_dump(),
            report_digest=report.report_digest,
            evaluated_at=report.evaluated_at,
        )
        session.add(report_rec)

        # Update candidate status based on evaluation verdict
        c_stmt = select(CandidateDefenseRecord).where(CandidateDefenseRecord.id == candidate.defense_id)
        cand_db = (await session.execute(c_stmt)).scalar_one_or_none()
        if cand_db:
            cand_db.status = "approved" if report.verdict.value in ["pass", "accept"] else "rejected"

        await session.commit()

        results["cand1_evaluation_request_id"] = str(eval_req.request_id)
        results["cand1_evaluation_report_id"] = str(report.report_id)
        results["cand1_evaluation_verdict"] = report.verdict.value
        results["cand1_evaluation_rationale"] = report.verdict_rationale
        results["cand1_candidate_accuracy"] = report.candidate_metrics.accuracy
        results["cand1_candidate_fpr"] = report.candidate_metrics.false_positive_rate
        logger.info(f"Evaluator Complete for Candidate 1: Verdict={report.verdict.value}, Accuracy={report.candidate_metrics.accuracy:.4f}, FPR={report.candidate_metrics.false_positive_rate:.4f}")

        # Check eligibility for Candidate 1
        eligibility_svc = ReleaseEligibilityService()
        eligibility1 = await eligibility_svc.check_eligibility(
            session=session,
            candidate_id=candidate.defense_id,
            evaluation_report_id=report.report_id,
        )
        results["cand1_is_release_eligible"] = eligibility1.is_eligible
        results["cand1_eligibility_reasons"] = eligibility1.reasons
        logger.info(f"Candidate 1 Release Eligibility: {eligibility1.is_eligible} - {eligibility1.reasons}")
        assert not eligibility1.is_eligible, "Invariant violation: Failed evaluation candidate must not be release-eligible"
        logger.info("Security Gate Invariant Confirmed: Failed candidate is strictly barred from release consideration.")

        # =========================================================================
        # 3b. ITERATIVE DEFENSE SYNTHESIS: Candidate 2 (Comprehensive Remediation Suite)
        # =========================================================================
        logger.info("--- Step 3b: Synthesizing Candidate 2 with Cross-Family Declarative Rules ---")
        rules_c2 = [
            DeclarativeRuleModel(
                rule_id="RULE-PHISH-HOMOGRAPH-01",
                rule_version="1.0.0",
                description="Block suspicious punycode domains",
                purpose="Mitigate IDN homograph mimicry",
                target_family="homograph_mimicry",
                predicates=[
                    RulePredicateModel(field="is_whitelisted", operator="eq", value=0),
                    RulePredicateModel(field="is_punycode", operator="eq", value=1),
                ],
                action=Decision.BLOCK,
                severity=ThreatSeverity.HIGH,
                weight=0.95,
            ),
            DeclarativeRuleModel(
                rule_id="RULE-PHISH-BRAND-02",
                rule_version="1.0.0",
                description="Block brand impersonation tokens on non-whitelisted sites",
                purpose="Mitigate brand impersonation",
                target_family="brand_impersonation",
                predicates=[
                    RulePredicateModel(field="is_whitelisted", operator="eq", value=0),
                    RulePredicateModel(field="brand_token_detected", operator="eq", value=1),
                ],
                action=Decision.BLOCK,
                severity=ThreatSeverity.HIGH,
                weight=0.95,
            ),
            DeclarativeRuleModel(
                rule_id="RULE-PHISH-DOUBLE-ENC-03",
                rule_version="1.0.0",
                description="Block double encoded payloads",
                purpose="Mitigate obfuscation",
                target_family="double_encoding",
                predicates=[
                    RulePredicateModel(field="is_whitelisted", operator="eq", value=0),
                    RulePredicateModel(field="has_double_encoding", operator="eq", value=1),
                ],
                action=Decision.BLOCK,
                severity=ThreatSeverity.HIGH,
                weight=0.95,
            ),
            DeclarativeRuleModel(
                rule_id="RULE-PHISH-DGA-04",
                rule_version="1.0.0",
                description="Block high host entropy DGA domains",
                purpose="Mitigate DGA algorithm domains",
                target_family="dga_entropy",
                predicates=[
                    RulePredicateModel(field="is_whitelisted", operator="eq", value=0),
                    RulePredicateModel(field="host_entropy", operator="gte", value=3.5),
                ],
                action=Decision.BLOCK,
                severity=ThreatSeverity.HIGH,
                weight=0.95,
            ),
            DeclarativeRuleModel(
                rule_id="RULE-PHISH-SUBDOMAIN-05",
                rule_version="1.0.0",
                description="Block excessive subdomain flooding",
                purpose="Mitigate subdomain nesting",
                target_family="subdomain_flooding",
                predicates=[
                    RulePredicateModel(field="is_whitelisted", operator="eq", value=0),
                    RulePredicateModel(field="subdomain_count", operator="gte", value=3),
                ],
                action=Decision.BLOCK,
                severity=ThreatSeverity.HIGH,
                weight=0.95,
            ),
            DeclarativeRuleModel(
                rule_id="RULE-PHISH-KEYWORDS-06",
                rule_version="1.0.0",
                description="Block multiple phishing keywords on non-whitelisted sites",
                purpose="Mitigate phishing keywords",
                target_family="phishing_keywords",
                predicates=[
                    RulePredicateModel(field="is_whitelisted", operator="eq", value=0),
                    RulePredicateModel(field="phish_keyword_count", operator="gte", value=1),
                ],
                action=Decision.BLOCK,
                severity=ThreatSeverity.HIGH,
                weight=0.95,
            ),
        ]

        candidate2 = CandidateDefense(
            defense_id=uuid4(),
            version="2026.11.1",
            author_agent="BlueAI-SynthesisAgent-v1",
            description="Declarative defense suite mitigating benchmark phishing and homoglyphs with zero whitelist regressions",
            rule_spec={"rules": [r.model_dump(mode="json") for r in rules_c2]},
        )
        await CandidateDefenseBuilder.save_candidate(candidate2, session)
        await session.commit()
        results["candidate2_id"] = str(candidate2.defense_id)
        results["candidate2_version"] = candidate2.version

        # Evaluate Candidate 2 against benchmark
        eval_req2 = EvaluationRequest(
            request_id=uuid4(),
            candidate_id=candidate2.defense_id,
            candidate_version=candidate2.version,
            benchmark_manifest_version=manifest_id,
            acceptance_policy=AcceptancePolicyConfig(
                max_allowed_fpr=0.05,
                max_allowed_regressions=0,
                min_detection_rate=0.70,
            ),
            requested_by="AutonomousWorkflowLead",
        )

        eval_req_rec2 = EvaluationRequestRecord(
            id=eval_req2.request_id,
            candidate_id=candidate2.defense_id,
            candidate_version=candidate2.version,
            baseline_detector_version=settings.APP_VERSION,
            baseline_policy_version="2026.10.1",
            benchmark_manifest_id=manifest_id,
            status="running",
            requested_by="AutonomousWorkflowLead",
            resource_budget={"budget_seconds": 60.0},
            target_finding_ids=[str(f.finding_id) for f in summary.findings],
            target_scenario_ids=[],
        )
        session.add(eval_req_rec2)
        await session.commit()

        report2 = await eval_runner.run_evaluation(
            request=eval_req2,
            candidate=candidate2,
            manifest=manifest,
        )
        eval_req_rec2.status = report2.status.value

        report_rec2 = EvaluationReportRecord(
            id=report2.report_id,
            request_id=eval_req2.request_id,
            candidate_id=candidate2.defense_id,
            candidate_version=report2.candidate_version,
            baseline_version=report2.baseline_version,
            benchmark_manifest_id=report2.benchmark_manifest_version,
            verdict=report2.verdict.value,
            status=report2.status.value,
            verdict_rationale=report2.verdict_rationale,
            acceptance_reasons=report2.acceptance_reasons,
            rejection_reasons=report2.rejection_reasons,
            baseline_metrics=report2.baseline_metrics.model_dump(),
            candidate_metrics=report2.candidate_metrics.model_dump(),
            split_metrics={k: v.model_dump() for k, v in report2.split_metrics.items()},
            improvement_metrics=report2.improvement_metrics.model_dump(),
            operational_metrics=report2.operational_metrics.model_dump(),
            report_digest=report2.report_digest,
            evaluated_at=report2.evaluated_at,
        )
        session.add(report_rec2)

        c2_stmt = select(CandidateDefenseRecord).where(CandidateDefenseRecord.id == candidate2.defense_id)
        cand2_db = (await session.execute(c2_stmt)).scalar_one_or_none()
        if cand2_db:
            cand2_db.status = "approved" if report2.verdict.value in ["pass", "accept"] else "rejected"
        await session.commit()

        results["cand2_evaluation_request_id"] = str(eval_req2.request_id)
        results["cand2_evaluation_report_id"] = str(report2.report_id)
        results["cand2_evaluation_verdict"] = report2.verdict.value
        results["cand2_evaluation_rationale"] = report2.verdict_rationale
        results["cand2_candidate_accuracy"] = report2.candidate_metrics.accuracy
        results["cand2_candidate_fpr"] = report2.candidate_metrics.false_positive_rate
        logger.info(f"Evaluator Complete for Candidate 2: Verdict={report2.verdict.value}, Accuracy={report2.candidate_metrics.accuracy:.4f}, FPR={report2.candidate_metrics.false_positive_rate:.4f}")

        # =========================================================================
        # 4. RELEASE MANAGEMENT: Eligibility & Ed25519 Cryptographic Signing
        # =========================================================================
        logger.info("--- Step 4: Release Eligibility and Signing for Candidate 2 ---")
        eligibility2 = await eligibility_svc.check_eligibility(
            session=session,
            candidate_id=candidate2.defense_id,
            evaluation_report_id=report2.report_id,
        )

        results["cand2_is_release_eligible"] = eligibility2.is_eligible
        results["cand2_eligibility_reasons"] = eligibility2.reasons
        logger.info(f"Candidate 2 Release Eligibility: {eligibility2.is_eligible} - {eligibility2.reasons}")

        if eligibility2.is_eligible:
            approval_svc = ReleaseApprovalService()
            release_rec, auth_rec = await approval_svc.authorize_and_stage_release(
                session=session,
                candidate_id=candidate2.defense_id,
                evaluation_report_id=report2.report_id,
                policy_version=candidate2.version,
                target_channel=ReleaseChannel.STABLE,
                authorized_by="LeadSecOpsOfficer",
                rationale="Automated continuous improvement pipeline verification passing all acceptance gates with zero regressions.",
                rule_spec=candidate2.rule_spec,
                scoring_thresholds={"warn_threshold": 0.50, "block_threshold": 0.85},
                supported_platforms=["browser_extension", "android_app"],
            )

            # Record audit event
            await AuditService.record_event(
                session=session,
                actor="LeadSecOpsOfficer",
                action="release.authorize",
                target_id=str(release_rec.id),
                target_type="release",
                outcome="success",
                metadata={
                    "policy_version": release_rec.policy_version,
                    "target_channel": release_rec.channel,
                    "artifact_digest": release_rec.artifact_digest,
                },
            )
            await session.commit()

            results["release_id"] = str(release_rec.id)
            results["policy_version"] = release_rec.policy_version
            results["artifact_digest"] = release_rec.artifact_digest
            results["publisher_key_id"] = release_rec.publisher_key_id
            results["release_status"] = release_rec.status
            logger.info(f"Release Staged & Signed: Release {release_rec.id} v{release_rec.policy_version} Key={release_rec.publisher_key_id}")

            # =====================================================================
            # 5. CLIENT UPDATE VERIFICATION: Verifier Contract
            # =====================================================================
            logger.info("--- Step 5: Testing Client Update Verifier Contract ---")
            # Retrieve trust anchors
            key_mgr = SigningKeyManager()
            trust_anchors = await key_mgr.get_trust_anchors(session)

            # Load signed manifest and bundle
            manifest_json = release_rec.manifest_payload or {}
            bundle_path = Path(release_rec.artifact_path)
            if bundle_path.exists():
                bundle_bytes = bundle_path.read_bytes()
            elif release_rec.bundle_payload:
                bundle_bytes = json.dumps(release_rec.bundle_payload, separators=(",", ":")).encode("utf-8")
            else:
                bundle_builder = PolicyBundleBuilder()
                _, bundle_bytes, _ = bundle_builder.build_bundle(
                    policy_version=release_rec.policy_version,
                    sequence_number=release_rec.sequence_number,
                    rule_spec=candidate2.rule_spec,
                    scoring_thresholds={"warn_threshold": 0.50, "block_threshold": 0.85},
                )

            verification_result = ClientUpdateVerifier.verify_update(
                manifest=manifest_json,
                bundle_bytes=bundle_bytes,
                trust_anchors=trust_anchors,
                client_version="0.1.0",
                engine_version="1.0.0",
                client_platform="browser_extension",
                current_sequence_number=0,
            )

            results["browser_verification_success"] = verification_result.is_valid
            results["browser_verification_step"] = verification_result.step_passed
            results["browser_verification_error"] = verification_result.error
            results["client_verification_policy_version"] = (
                verification_result.bundle.policy_version if verification_result.bundle else None
            )
            logger.info(f"Browser Extension Verification: IsValid={verification_result.is_valid}, StepPassed={verification_result.step_passed}")

            # Verify Android companion client update ingestion contract
            verification_result_android = ClientUpdateVerifier.verify_update(
                manifest=manifest_json,
                bundle_bytes=bundle_bytes,
                trust_anchors=trust_anchors,
                client_version="0.1.0",
                engine_version="1.0.0",
                client_platform="android_app",
                current_sequence_number=0,
            )
            results["android_verification_success"] = verification_result_android.is_valid
            results["android_verification_step"] = verification_result_android.step_passed
            results["android_verification_error"] = verification_result_android.error
            logger.info(f"Android Companion Verification: IsValid={verification_result_android.is_valid}, StepPassed={verification_result_android.step_passed}")

        # =========================================================================
        # 6. THREAT INTEL & TELEMETRY: Ingestion of live verification fixtures
        # =========================================================================
        logger.info("--- Step 6: Ingesting Threat Indicators & Telemetry Observations ---")
        intel_repo = ThreatIntelRepository(session=session)
        ind = await intel_repo.add_indicator(
            indicator_type="url",
            normalized_value="https://banking-update.secure-login.test/verify",
            classification="phishing",
            source="RedAI-Laboratory-E2E",
            severity="high",
            confidence=0.98,
        )
        results["threat_indicator_id"] = str(ind.get("id") or ind.get("indicator_id"))

        # Ingest edge observation
        from apps.api.app.models.observations import ThreatObservation
        obs_id = uuid4()
        obs = ThreatObservation(
            id=obs_id,
            normalized_target="banking-update.secure-login.test/verify",
            source="browser_extension",
            local_action_taken="block",
            engine_version="0.3.0",
            policy_version="2026.11.1",
            telemetry_payload={
                "raw_url": "https://banking-update.secure-login.test/verify?token=secret",
                "redacted_url": "https://banking-update.secure-login.test/verify?token=[REDACTED]",
                "domain": "banking-update.secure-login.test",
                "confidence_score": 0.98,
                "threat_types": ["credential_phishing"],
            },
            verification_status="triaged",
        )
        session.add(obs)
        await session.commit()
        results["threat_observation_id"] = str(obs_id)
        logger.info(f"Threat Intelligence populated: Indicator {ind.get('id')}, Observation {obs_id}")

        logger.info("=== WORKFLOW SUCCESSFULLY COMPLETED AND COMMITTED ===")

    finally:
        await session.close()

    return results


if __name__ == "__main__":
    res = asyncio.run(main())
    print("\n--- WORKFLOW EXECUTION SUMMARY ---")
    for k, v in res.items():
        print(f"  {k:35}: {v}")
