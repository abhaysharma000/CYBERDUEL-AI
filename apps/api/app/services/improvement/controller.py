"""Autonomous Self-Improvement Controller orchestrating bounded Red-Blue-Evaluator cycles."""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from cyberduel_contracts.enums import (
    CycleStatus,
    DefenseStatus,
    EvaluationStatus,
    EvaluationVerdict,
)
from cyberduel_contracts.evaluation import (
    EvaluationReport,
    EvaluationRequest,
    ImprovementCycleSummary,
)
from cyberduel_contracts.policy import CandidateDefense, DeclarativeRuleModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.evaluations import (
    BenchmarkManifestRecord,
    CycleFeedbackRecord,
    EvaluationReportRecord,
    EvaluationRequestRecord,
    ImprovementCycleRecord,
)
from apps.api.app.models.lab import FailureFindingRecord
from apps.api.app.models.policies import (
    CandidateDefenseRecord,
    CandidateFeedbackRecord,
)
from apps.api.app.services.blue_ai import (
    CandidateDefenseBuilder,
    CandidateSandboxRunner,
    DefenseHypothesisEngine,
    DefenseProposalGenerator,
    LearningFeedbackService,
)
from apps.api.app.services.blue_ai.prioritizer import FailureCluster, PrioritizedFailureGroup
from apps.api.app.services.improvement.analytics import ImprovementAnalyticsService
from apps.api.app.services.improvement.checkpoints import CheckpointManager
from apps.api.app.services.improvement.policy import ControllerPolicyConfig
from services.evaluator.app.benchmarks import BenchmarkRegistry
from services.evaluator.app.runner import EvaluationRunner

logger = logging.getLogger("improvement.controller")


class SelfImprovementController:
    """Orchestrates bounded, leak-free self-improvement loops across Red AI, Blue AI, and Evaluator."""

    def __init__(
        self,
        session: AsyncSession,
        benchmark_registry: BenchmarkRegistry | None = None,
        evaluation_runner: EvaluationRunner | None = None,
    ) -> None:
        self.session = session
        self.benchmark_registry = benchmark_registry or BenchmarkRegistry()
        self.evaluation_runner = evaluation_runner or EvaluationRunner(
            benchmark_registry=self.benchmark_registry
        )

    async def execute_cycle(
        self,
        config: ControllerPolicyConfig | None = None,
        trigger_reason: str = "scheduled_research_loop",
    ) -> ImprovementCycleSummary:
        """Run the 10-step bounded autonomous self-improvement cycle."""
        policy_cfg = config or ControllerPolicyConfig()
        start_time = time.perf_counter()
        cycle_id = uuid4()

        # Determine cycle number
        stmt_max = select(func.max(ImprovementCycleRecord.cycle_number))
        res_max = await self.session.execute(stmt_max)
        current_max = res_max.scalar() or 0
        cycle_number = current_max + 1

        cycle_record = ImprovementCycleRecord(
            id=cycle_id,
            cycle_number=cycle_number,
            status=CycleStatus.RUNNING.value,
            trigger_reason=trigger_reason,
            configuration=policy_cfg.model_dump(),
            selected_findings=[],
            candidates_evaluated=0,
            accepted_candidate_id=None,
            accepted_candidate_version=None,
            summary_metrics={},
            terminal_reason="",
            started_at=datetime.now(UTC),
        )
        self.session.add(cycle_record)
        await self.session.flush()

        logger.info(f"Initiated Self-Improvement Cycle #{cycle_number} ({cycle_id})")

        # Track evaluated candidate rule digests for deduplication
        evaluated_digests: set[str] = set()
        candidates_evaluated = 0
        accepted_candidate: CandidateDefenseRecord | None = None
        terminal_status = CycleStatus.COMPLETED
        terminal_reason = ""

        try:
            # =========================================================================
            # STEP 1: Select research opportunities from Red AI experiments
            # =========================================================================
            findings = await self._step1_select_opportunities(policy_cfg)
            selected_ids = [str(f.id) for f in findings]
            cycle_record.selected_findings = selected_ids
            await CheckpointManager.record_checkpoint(
                self.session,
                cycle_id=cycle_id,
                step_number=1,
                step_name="SELECT_OPPORTUNITIES",
                details={
                    "findings_count": len(findings),
                    "finding_ids": selected_ids,
                    "categories": list({f.failure_category for f in findings}),
                },
            )

            if not findings:
                terminal_status = CycleStatus.STOPPED_NO_PROGRESS
                terminal_reason = "No open Red AI failure findings found for investigation"
                return await self._finalize_cycle(
                    cycle_record,
                    status=terminal_status,
                    reason=terminal_reason,
                    start_time=start_time,
                )

            # Iteration loop bounded by max_candidates_per_cycle
            while candidates_evaluated < policy_cfg.max_candidates_per_cycle:
                # Check wall-clock timeout
                elapsed = time.perf_counter() - start_time
                if elapsed >= policy_cfg.cycle_timeout_seconds:
                    terminal_status = CycleStatus.STOPPED_BUDGET_EXHAUSTED
                    terminal_reason = f"Cycle timeout reached ({elapsed:.1f}s >= {policy_cfg.cycle_timeout_seconds}s)"
                    break

                target_finding = findings[candidates_evaluated % len(findings)]

                # =====================================================================
                # STEP 2: Request Blue AI candidate defenses
                # =====================================================================
                candidate_rec = await self._step2_generate_candidate(target_finding)
                if not candidate_rec:
                    terminal_status = CycleStatus.STOPPED_NO_PROGRESS
                    terminal_reason = "Blue AI failed to generate candidate defense proposal"
                    break

                await CheckpointManager.record_checkpoint(
                    self.session,
                    cycle_id=cycle_id,
                    step_number=2,
                    step_name="GENERATE_CANDIDATE",
                    details={
                        "candidate_id": str(candidate_rec.id),
                        "candidate_version": candidate_rec.version,
                        "target_finding_id": str(target_finding.id),
                    },
                )

                # =====================================================================
                # STEP 3: Validate candidate defense (allowlist, safe regex, digest)
                # =====================================================================
                is_valid, digest, validation_msg = self._step3_validate_candidate(candidate_rec)
                await CheckpointManager.record_checkpoint(
                    self.session,
                    cycle_id=cycle_id,
                    step_number=3,
                    step_name="VALIDATE_CANDIDATE",
                    details={
                        "is_valid": is_valid,
                        "digest": digest,
                        "message": validation_msg,
                    },
                )

                if not is_valid:
                    logger.warning(
                        f"Candidate {candidate_rec.version} validation failed: {validation_msg}"
                    )
                    candidates_evaluated += 1
                    continue

                if digest in evaluated_digests:
                    logger.info(
                        f"Duplicate candidate digest {digest[:8]} skipped for deduplication"
                    )
                    candidates_evaluated += 1
                    continue

                evaluated_digests.add(digest)

                # =====================================================================
                # STEP 4: Run preliminary candidate checks in sandbox
                # =====================================================================
                contract_candidate = CandidateDefense(
                    defense_id=candidate_rec.id,
                    version=candidate_rec.version,
                    author_agent=candidate_rec.author_agent,
                    description=candidate_rec.description,
                    rule_spec=candidate_rec.rule_spec,
                    status=DefenseStatus.CANDIDATE,
                )
                prelim_ok, prelim_summary = await self._step4_preliminary_checks(contract_candidate)
                await CheckpointManager.record_checkpoint(
                    self.session,
                    cycle_id=cycle_id,
                    step_number=4,
                    step_name="PRELIMINARY_CHECKS",
                    details=prelim_summary,
                )

                if not prelim_ok:
                    logger.info(
                        f"Candidate {candidate_rec.version} failed preliminary checks: {prelim_summary}"
                    )
                    candidates_evaluated += 1
                    continue

                # =====================================================================
                # STEP 5: Request independent evaluation on frozen benchmarks
                # =====================================================================
                eval_request_rec, eval_report = await self._step5_request_evaluation(
                    candidate_rec=candidate_rec,
                    contract_candidate=contract_candidate,
                    policy_cfg=policy_cfg,
                    target_finding=target_finding,
                )
                await CheckpointManager.record_checkpoint(
                    self.session,
                    cycle_id=cycle_id,
                    step_number=5,
                    step_name="SUBMIT_EVALUATION",
                    details={
                        "evaluation_request_id": str(eval_request_rec.id),
                        "benchmark_manifest": eval_request_rec.benchmark_manifest_id,
                        "verdict": eval_report.verdict.value,
                    },
                )

                candidates_evaluated += 1
                cycle_record.candidates_evaluated = candidates_evaluated

                # =====================================================================
                # STEP 6: Record evaluation report and audit findings
                # =====================================================================
                await self._step6_record_report(eval_request_rec, eval_report, candidate_rec)
                await CheckpointManager.record_checkpoint(
                    self.session,
                    cycle_id=cycle_id,
                    step_number=6,
                    step_name="RECORD_EVALUATION",
                    details={
                        "report_id": str(eval_report.report_id),
                        "verdict": eval_report.verdict.value,
                        "recall": eval_report.candidate_metrics.recall,
                        "fpr": eval_report.candidate_metrics.false_positive_rate,
                        "regressions": eval_report.improvement_metrics.new_regressions,
                        "resolved": eval_report.improvement_metrics.original_failures_resolved,
                    },
                )

                # =====================================================================
                # STEP 7: Provide learning feedback to Blue AI
                # =====================================================================
                await self._step7_provide_feedback(cycle_id, candidate_rec, eval_report)
                await CheckpointManager.record_checkpoint(
                    self.session,
                    cycle_id=cycle_id,
                    step_number=7,
                    step_name="PROVIDE_FEEDBACK",
                    details={"feedback_sent_for": candidate_rec.version},
                )

                # =====================================================================
                # STEP 8: Decide next steps
                # =====================================================================
                if eval_report.verdict == EvaluationVerdict.PASS:
                    # Candidate Accepted! Mark as eligible for release
                    candidate_rec.status = DefenseStatus.APPROVED.value
                    accepted_candidate = candidate_rec
                    cycle_record.accepted_candidate_id = candidate_rec.id
                    cycle_record.accepted_candidate_version = candidate_rec.version

                    terminal_status = CycleStatus.COMPLETED
                    terminal_reason = (
                        f"Candidate {candidate_rec.version} successfully passed independent evaluation "
                        f"(Recall: {eval_report.candidate_metrics.recall:.2%}, FPR: {eval_report.candidate_metrics.false_positive_rate:.2%}, "
                        f"0 Regressions). Marked as eligible for release."
                    )
                    await CheckpointManager.record_checkpoint(
                        self.session,
                        cycle_id=cycle_id,
                        step_number=8,
                        step_name="DECIDE_NEXT_STEPS",
                        details={
                            "decision": "candidate_accepted",
                            "candidate_version": candidate_rec.version,
                            "eligible_for_release": True,
                        },
                    )
                    break
                else:
                    candidate_rec.status = DefenseStatus.REJECTED.value
                    await CheckpointManager.record_checkpoint(
                        self.session,
                        cycle_id=cycle_id,
                        step_number=8,
                        step_name="DECIDE_NEXT_STEPS",
                        details={
                            "decision": "candidate_rejected",
                            "reasons": eval_report.rejection_reasons,
                            "retry": candidates_evaluated < policy_cfg.max_candidates_per_cycle,
                        },
                    )

            # =========================================================================
            # STEP 9: Enforce autonomous resource controls & safe stopping
            # =========================================================================
            if not accepted_candidate and terminal_status == CycleStatus.COMPLETED:
                terminal_status = CycleStatus.STOPPED_BUDGET_EXHAUSTED
                terminal_reason = (
                    f"Candidate evaluation budget exhausted ({candidates_evaluated}/{policy_cfg.max_candidates_per_cycle}) "
                    f"without finding an acceptable defense."
                )

            await CheckpointManager.record_checkpoint(
                self.session,
                cycle_id=cycle_id,
                step_number=9,
                step_name="ENFORCE_RESOURCE_BOUNDS",
                details={
                    "candidates_evaluated": candidates_evaluated,
                    "budget_limit": policy_cfg.max_candidates_per_cycle,
                    "terminal_status": terminal_status.value,
                },
            )

        except Exception as ex:
            logger.exception(f"Error executing improvement cycle {cycle_id}: {ex}")
            with contextlib.suppress(Exception):
                await self.session.rollback()
            terminal_status = CycleStatus.FAILED
            terminal_reason = f"Fatal execution exception: {ex}"

        # =============================================================================
        # STEP 10: Finalize cycle record and summary
        # =============================================================================
        return await self._finalize_cycle(
            cycle_record,
            status=terminal_status,
            reason=terminal_reason,
            start_time=start_time,
        )

    async def _step1_select_opportunities(
        self,
        policy: ControllerPolicyConfig,
    ) -> list[FailureFindingRecord]:
        """Fetch open failure findings from Red AI experiments."""
        stmt = (
            select(FailureFindingRecord)
            .where(FailureFindingRecord.status == "open")
            .order_by(FailureFindingRecord.created_at.desc())
            .limit(10)
        )
        result = await self.session.execute(stmt)
        findings = list(result.scalars().all())

        if policy.target_failure_categories:
            findings = [
                f for f in findings if f.failure_category in policy.target_failure_categories
            ]

        # If no open failure findings exist in DB, create a synthetic fallback finding from golden failure
        if not findings:
            finding = FailureFindingRecord(
                id=uuid4(),
                experiment_id=uuid4(),
                failure_category="evasion",
                discrepancy_type="false_negative",
                hypothesis="Detector missed suspicious homograph mimicked domains",
                affected_scenarios_count=3,
                representative_scenario_ids=[],
                suggested_remedy="Formulate declarative homograph inspection rule",
                severity="high",
                status="open",
            )
            self.session.add(finding)
            await self.session.flush()
            findings = [finding]

        return findings

    async def _step2_generate_candidate(
        self,
        finding: FailureFindingRecord,
    ) -> CandidateDefenseRecord | None:
        """Invoke Blue AI hypothesis and proposal engines to synthesize candidate defense."""
        try:
            # 1. Build failure cluster and priority group
            sample_urls = [
                "https://xn--pple-43d.com/login",
                "http://192.168.1.1/login.php",
            ]
            cluster = FailureCluster(
                cluster_id=f"cluster-{finding.id}",
                failure_category=finding.failure_category,
                target_family=finding.failure_category,
                discrepancy_type=finding.discrepancy_type,
                severity=finding.severity,
                findings=[],
                scenarios=[],
                affected_count=finding.affected_scenarios_count,
                sample_urls=sample_urls,
            )
            p_group = PrioritizedFailureGroup(
                cluster=cluster,
                priority_score=0.92,
                urgency_rank=1,
                rationale=f"Investigation priority for {finding.failure_category}",
                recommended_focus=f"Mitigate {finding.failure_category}",
            )

            # 2. Formulate hypothesis
            task_id = uuid4()
            hypothesis = DefenseHypothesisEngine.formulate_hypothesis(
                task_id=task_id,
                priority_group=p_group,
            )

            # 3. Generate proposal
            proposal = DefenseProposalGenerator.generate_proposal(hypothesis)

            # 4. Assemble candidate defense contract
            candidate_contract = CandidateDefenseBuilder.assemble_candidate(
                proposals=[proposal],
                baseline_version="0.2.0",
                candidate_sequence=int(time.time() * 1000) % 100000,
            )
            candidate_contract.version = f"0.2.0-blue-{uuid4().hex[:6]}"

            # 5. Persist candidate defense in DB
            candidate_rec = await CandidateDefenseBuilder.save_candidate(
                candidate=candidate_contract,
                session=self.session,
            )
            return candidate_rec
        except Exception as e:
            logger.warning(f"Error generating candidate via Blue AI workflow: {e}")
            return None

    def _step3_validate_candidate(
        self,
        candidate_rec: CandidateDefenseRecord,
    ) -> tuple[bool, str, str]:
        """Verify candidate defense format, rule specs, and compute cryptographic digest."""
        if not candidate_rec.rule_spec:
            return (False, "", "rule_spec is empty")

        spec_bytes = json.dumps(candidate_rec.rule_spec, sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(spec_bytes).hexdigest()

        rules_list = candidate_rec.rule_spec.get("rules", [])
        if not isinstance(rules_list, list) or len(rules_list) == 0:
            return (False, digest, "No rules present in rule_spec")

        for r_dict in rules_list:
            try:
                DeclarativeRuleModel.model_validate(r_dict)
            except Exception as ex:
                return (False, digest, f"Invalid rule schema: {ex}")

        return (True, digest, "Candidate validated successfully")

    async def _step4_preliminary_checks(
        self,
        candidate: CandidateDefense,
    ) -> tuple[bool, dict[str, Any]]:
        """Run quick sandbox verification on standard benign controls."""
        try:
            comparison = await CandidateSandboxRunner.run_comparison(
                candidate=candidate,
                session=self.session,
            )
            summary = {
                "total_scenarios": comparison.total_scenarios_evaluated,
                "baseline_accuracy": comparison.baseline_accuracy,
                "candidate_accuracy": comparison.candidate_accuracy,
                "new_regressions": comparison.new_regressions,
                "new_false_positives": comparison.new_false_positives,
                "preliminary_verdict": comparison.preliminary_verdict,
            }
            # Reject immediately if blatant false positives or regressions appear on baseline controls
            if comparison.new_false_positives > 0 or comparison.new_regressions > 1:
                return (False, summary)
            return (True, summary)
        except Exception as ex:
            logger.warning(f"Preliminary check error: {ex}")
            return (False, {"error": str(ex)})

    async def _step5_request_evaluation(
        self,
        candidate_rec: CandidateDefenseRecord,
        contract_candidate: CandidateDefense,
        policy_cfg: ControllerPolicyConfig,
        target_finding: FailureFindingRecord,
    ) -> tuple[EvaluationRequestRecord, EvaluationReport]:
        """Submit formal evaluation request and execute independent benchmark audit."""
        manifest_id = policy_cfg.benchmark_manifest_version

        # Ensure manifest exists in database
        stmt_m = select(BenchmarkManifestRecord).where(BenchmarkManifestRecord.id == manifest_id)
        res_m = await self.session.execute(stmt_m)
        manifest_rec = res_m.scalar_one_or_none()

        bench_manifest = self.benchmark_registry.get_manifest(manifest_id)
        if bench_manifest is None:
            bench_manifest = self.benchmark_registry.create_default_golden_manifest()

        if manifest_rec is None:
            manifest_rec = BenchmarkManifestRecord(
                id=bench_manifest.manifest_id,
                name=bench_manifest.name,
                version=bench_manifest.version,
                description=bench_manifest.description,
                split_counts=bench_manifest.split_counts,
                family_counts=bench_manifest.family_counts,
                scenario_count=bench_manifest.scenario_count,
                scenarios_payload=[s.model_dump(mode="json") for s in bench_manifest.scenarios],
                integrity_hash=bench_manifest.integrity_hash,
            )
            self.session.add(manifest_rec)
            await self.session.flush()

        # Build EvaluationRequest
        request_id = uuid4()
        eval_request_obj = EvaluationRequest(
            request_id=request_id,
            candidate_id=candidate_rec.id,
            candidate_version=candidate_rec.version,
            benchmark_manifest_version=manifest_id,
            acceptance_policy=policy_cfg.acceptance_policy,
            target_finding_ids=[target_finding.id],
            target_scenario_ids=[],
            resource_budget_seconds=policy_cfg.cycle_timeout_seconds,
            requested_by="SelfImprovementController",
            status=EvaluationStatus.RUNNING,
        )

        eval_req_rec = EvaluationRequestRecord(
            id=request_id,
            candidate_id=candidate_rec.id,
            candidate_version=candidate_rec.version,
            baseline_detector_version="0.2.0-heuristic-intel",
            baseline_policy_version="2026.10.1",
            benchmark_manifest_id=manifest_id,
            status="running",
            requested_by="SelfImprovementController",
            resource_budget={"budget_seconds": policy_cfg.cycle_timeout_seconds},
            target_finding_ids=[str(target_finding.id)],
            target_scenario_ids=[],
            started_at=datetime.now(UTC),
        )
        self.session.add(eval_req_rec)
        await self.session.flush()

        # Run independent evaluation
        report = await self.evaluation_runner.run_evaluation(
            request=eval_request_obj,
            candidate=contract_candidate,
            manifest=bench_manifest,
        )

        eval_req_rec.status = report.status.value
        eval_req_rec.completed_at = datetime.now(UTC)
        await self.session.flush()

        return (eval_req_rec, report)

    async def _step6_record_report(
        self,
        eval_req_rec: EvaluationRequestRecord,
        report: EvaluationReport,
        candidate_rec: CandidateDefenseRecord,
    ) -> None:
        """Persist EvaluationReportRecord and CandidateFeedbackRecord in database."""
        report_rec = EvaluationReportRecord(
            id=report.report_id,
            request_id=eval_req_rec.id,
            candidate_id=candidate_rec.id,
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
        self.session.add(report_rec)

        feedback_rec = CandidateFeedbackRecord(
            id=uuid4(),
            candidate_id=candidate_rec.id,
            evaluator_verdict=report.verdict.value,
            evaluator_rationale=report.verdict_rationale,
            detection_rate=report.candidate_metrics.recall,
            false_positive_rate=report.candidate_metrics.false_positive_rate,
            regression_count=report.improvement_metrics.new_regressions,
            details={
                "report_id": str(report.report_id),
                "rejection_reasons": report.rejection_reasons,
                "acceptance_reasons": report.acceptance_reasons,
            },
        )
        self.session.add(feedback_rec)
        await self.session.flush()

    async def _step7_provide_feedback(
        self,
        cycle_id: UUID,
        candidate_rec: CandidateDefenseRecord,
        report: EvaluationReport,
    ) -> None:
        """Provide structured feedback to Blue AI to prevent re-testing failed patterns."""
        feedback_type = "independent_eval_verdict"
        lessons = (
            f"Verdict: {report.verdict.value.upper()}. "
            f"Recall: {report.candidate_metrics.recall:.2%}, FPR: {report.candidate_metrics.false_positive_rate:.2%}. "
            f"Regressions: {report.improvement_metrics.new_regressions}. "
            f"Notes: {report.verdict_rationale}"
        )

        cycle_feedback = CycleFeedbackRecord(
            id=uuid4(),
            cycle_id=cycle_id,
            candidate_id=candidate_rec.id,
            feedback_type=feedback_type,
            outcome=report.status.value,
            lessons_learned=lessons,
            feature_weights={
                "recall_weight": 0.5,
                "fpr_penalty": 1.0,
                "regression_penalty": 2.0,
            },
            created_at=datetime.now(UTC),
        )
        self.session.add(cycle_feedback)
        await self.session.flush()

        try:
            from cyberduel_contracts.evaluation import EvaluationResult

            eval_res = EvaluationResult(
                evaluation_id=report.report_id,
                candidate_defense_id=candidate_rec.id,
                scenario_suite_id=report.benchmark_manifest_version,
                total_scenarios=report.candidate_metrics.total,
                passed_scenarios=report.candidate_metrics.tp + report.candidate_metrics.tn,
                detection_rate=report.candidate_metrics.recall,
                false_positive_rate=report.candidate_metrics.false_positive_rate,
                regression_count=report.improvement_metrics.new_regressions,
                resource_overhead_ms=report.operational_metrics.mean_latency_ms,
                verdict=report.verdict,
                verdict_rationale=report.verdict_rationale,
            )
            cand_contract = CandidateDefense(
                defense_id=candidate_rec.id,
                version=candidate_rec.version,
                author_agent=candidate_rec.author_agent,
                description=candidate_rec.description,
                rule_spec=candidate_rec.rule_spec,
            )
            await LearningFeedbackService.record_feedback(
                candidate=cand_contract,
                evaluation_result=eval_res,
                session=self.session,
            )
        except Exception as e:
            logger.warning(f"Error updating Blue AI learning feedback: {e}")

    async def _finalize_cycle(
        self,
        cycle_record: ImprovementCycleRecord,
        status: CycleStatus,
        reason: str,
        start_time: float,
    ) -> ImprovementCycleSummary:
        """Complete the improvement cycle and persist terminal state."""
        duration = max(0.0, time.perf_counter() - start_time)
        cycle_record.status = status.value
        cycle_record.terminal_reason = reason
        cycle_record.completed_at = datetime.now(UTC)
        cycle_record.summary_metrics = {
            "duration_seconds": round(duration, 2),
            "candidates_evaluated": cycle_record.candidates_evaluated,
            "accepted_candidate_version": cycle_record.accepted_candidate_version,
            "budget_used_pct": round(
                (
                    cycle_record.candidates_evaluated
                    / max(1, cycle_record.configuration.get("max_candidates_per_cycle", 5))
                )
                * 100.0,
                1,
            ),
        }

        await CheckpointManager.record_checkpoint(
            self.session,
            cycle_id=cycle_record.id,
            step_number=10,
            step_name="CYCLE_FINALIZED",
            details={
                "status": status.value,
                "reason": reason,
                "duration_seconds": round(duration, 2),
            },
        )
        await self.session.commit()

        logger.info(
            f"Cycle #{cycle_record.cycle_number} finalized with status {status.value} in {duration:.2f}s: {reason}"
        )

        summary = await ImprovementAnalyticsService.get_cycle_summary(self.session, cycle_record.id)
        if summary is None:
            raise RuntimeError(f"Failed to retrieve summary for finalized cycle {cycle_record.id}")
        return summary
