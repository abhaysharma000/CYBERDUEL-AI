"""Blue AI Autonomous Research Agent.

Orchestrates the 10-stage defensive cycle: ingesting Red AI findings, prioritizing gaps,
formulating hypotheses, generating declarative rules, running sandbox comparisons,
compiling evidence, submitting for independent benchmark evaluation, and recording feedback.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from cyberduel_contracts.evaluation import EvaluationResult
from cyberduel_contracts.lab import EvaluationHandoffPackage, ScenarioContract
from cyberduel_contracts.policy import (
    BaselineComparisonReport,
    CandidateDefense,
    CandidateFeedback,
    DefenseProposal,
    DefensiveHypothesis,
)
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.services.blue_ai.builder import CandidateDefenseBuilder
from apps.api.app.services.blue_ai.evidence import DefenseEvidenceService
from apps.api.app.services.blue_ai.feedback import LearningFeedbackService
from apps.api.app.services.blue_ai.handoff import EvaluationHandoffService
from apps.api.app.services.blue_ai.hypothesis import DefenseHypothesisEngine
from apps.api.app.services.blue_ai.prioritizer import PrioritizedFailureGroup
from apps.api.app.services.blue_ai.proposals import DefenseProposalGenerator
from apps.api.app.services.blue_ai.research import DefensiveResearchService
from apps.api.app.services.blue_ai.sandbox_runner import CandidateSandboxRunner

logger = logging.getLogger("blue_ai.agent")


@dataclass
class BlueCycleResult:
    """Consolidated outcome of an end-to-end Blue AI research and defense proposal cycle."""

    task_id: UUID
    candidate: CandidateDefense
    hypothesis: DefensiveHypothesis
    proposal: DefenseProposal
    comparison_report: BaselineComparisonReport
    evidence_dossier: dict[str, Any]
    evaluation_result: EvaluationResult
    feedback: CandidateFeedback
    summary: dict[str, Any]


class BlueResearchAgent:
    """Coordinates autonomous defensive research, candidate formulation, and benchmark submission."""

    def __init__(
        self,
        handoff_service: EvaluationHandoffService | None = None,
    ) -> None:
        self.handoff_service = handoff_service or EvaluationHandoffService()

    async def run_cycle(
        self,
        handoff_package: EvaluationHandoffPackage,
        candidate_sequence: int = 1,
        evaluation_suite_id: str = "curated-golden-v1",
        session: AsyncSession | None = None,
    ) -> BlueCycleResult:
        """Execute full 10-step defensive research cycle."""
        logger.info(
            f"=== Starting Blue AI Research Cycle for Handoff {handoff_package.handoff_id} ==="
        )

        # Stage 1: Ingest Findings & Initiate Research Task
        rejected_categories = await LearningFeedbackService.get_rejected_categories(session)
        task_record, ranked_groups = await DefensiveResearchService.ingest_handoff(
            handoff=handoff_package,
            session=session,
            rejected_categories=rejected_categories,
        )

        if not ranked_groups:
            raise ValueError("No actionable failure clusters found in handoff package.")

        # Stage 2 & 3: Select Top-Priority Failure Cluster
        top_group: PrioritizedFailureGroup = ranked_groups[0]
        logger.info(
            f"Top priority selected: {top_group.cluster.failure_category} "
            f"(Score: {top_group.priority_score:.2f}, Rank: {top_group.urgency_rank})"
        )

        # Stage 4: Formulate Defensive Hypothesis (via QwenProvider if configured, else procedural)
        hypothesis = await DefenseHypothesisEngine.formulate_hypothesis_async(
            task_id=task_record.id,
            priority_group=top_group,
        )
        if session is not None:
            await DefenseHypothesisEngine.save_hypothesis(hypothesis, session)
        logger.info(f"Formulated hypothesis: {hypothesis.possible_explanation[:120]}...")

        # Stage 5: Generate Concrete Defense Proposal (Safe Declarative Rule)
        proposal = await DefenseProposalGenerator.generate_proposal_async(hypothesis)
        if session is not None:
            await DefenseProposalGenerator.save_proposal(proposal, session)
        logger.info(f"Generated proposal '{proposal.title}' (Type: {proposal.proposal_type.value})")

        # Stage 6: Assemble Candidate Defense
        candidate = CandidateDefenseBuilder.assemble_candidate(
            proposals=[proposal],
            baseline_version=handoff_package.policy_version or "1.0.0",
            candidate_sequence=candidate_sequence,
        )
        if session is not None:
            await CandidateDefenseBuilder.save_candidate(candidate, session)
        digest_str = str(candidate.rule_spec.get("digest") or "")[:12]
        logger.info(
            f"Assembled CandidateDefense version {candidate.version} (Digest: {digest_str}...)"
        )

        # Stage 7: Run Candidate Sandbox Comparative Evaluation
        failing_scenarios: list[ScenarioContract] = top_group.cluster.scenarios
        comparison_report = await CandidateSandboxRunner.run_comparison(
            candidate=candidate,
            failing_scenarios=failing_scenarios,
            session=session,
        )
        logger.info(
            f"Sandbox Comparison Verdict: {comparison_report.preliminary_verdict.upper()} "
            f"(Fixed: {comparison_report.original_failures_resolved}, Regressions: {comparison_report.new_regressions}, FPR: {comparison_report.candidate_fpr:.2%})"
        )

        # Stage 8: Compile Evidence Dossier
        evidence_dossier = DefenseEvidenceService.compile_dossier(
            candidate=candidate,
            hypotheses=[hypothesis],
            proposals=[proposal],
            comparison=comparison_report,
            experiment_id=str(handoff_package.experiment_id)
            if handoff_package.experiment_id
            else None,
        )
        fp_str = str(evidence_dossier.get("dossier_fingerprint") or "")[:12]
        logger.info(f"Compiled Evidence Dossier (Fingerprint: {fp_str}...)")

        # Stage 9: Hand Off to Independent Evaluator for Release Qualification
        eval_result = await self.handoff_service.submit_candidate(
            candidate=candidate,
            suite_id=evaluation_suite_id,
            session=session,
        )
        logger.info(f"Independent Evaluator Verdict: {eval_result.verdict.value.upper()}")

        # Stage 10: Learn from Feedback
        feedback = await LearningFeedbackService.record_feedback(
            candidate=candidate,
            evaluation_result=eval_result,
            session=session,
        )
        logger.info(f"Recorded Evaluation Feedback (Verdict: {feedback.evaluator_verdict.value})")

        cycle_summary = {
            "task_id": str(task_record.id),
            "candidate_id": str(candidate.defense_id),
            "candidate_version": candidate.version,
            "target_category": top_group.cluster.failure_category,
            "sandbox_verdict": comparison_report.preliminary_verdict,
            "evaluator_verdict": eval_result.verdict.value,
            "failures_resolved": comparison_report.original_failures_resolved,
            "regressions": comparison_report.new_regressions,
            "candidate_fpr": comparison_report.candidate_fpr,
            "completed_at": datetime.now(UTC).isoformat(),
        }

        return BlueCycleResult(
            task_id=task_record.id,
            candidate=candidate,
            hypothesis=hypothesis,
            proposal=proposal,
            comparison_report=comparison_report,
            evidence_dossier=evidence_dossier,
            evaluation_result=eval_result,
            feedback=feedback,
            summary=cycle_summary,
        )
