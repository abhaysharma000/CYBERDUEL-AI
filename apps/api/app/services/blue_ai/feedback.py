"""Learning feedback service for Blue AI.

Maintains historical memory of accepted and rejected candidate defenses,
extracting lessons from independent evaluation verdicts to improve future proposals.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from cyberduel_contracts.enums import EvaluationVerdict
from cyberduel_contracts.evaluation import EvaluationResult
from cyberduel_contracts.policy import CandidateDefense, CandidateFeedback
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.policies import CandidateFeedbackRecord

logger = logging.getLogger("blue_ai.feedback")


class LearningFeedbackService:
    """Records evaluation feedback and maintains adaptive learning memory for Blue AI."""

    _in_memory_feedback: list[CandidateFeedback] = []

    @classmethod
    async def record_feedback(
        cls,
        candidate: CandidateDefense,
        evaluation_result: EvaluationResult,
        session: AsyncSession | None = None,
    ) -> CandidateFeedback:
        """Record evaluation feedback from an independent benchmark audit."""
        feedback = CandidateFeedback(
            feedback_id=uuid4(),
            candidate_id=candidate.defense_id,
            evaluator_verdict=evaluation_result.verdict,
            evaluator_rationale=evaluation_result.verdict_rationale,
            detection_rate=evaluation_result.detection_rate,
            false_positive_rate=evaluation_result.false_positive_rate,
            regression_count=evaluation_result.regression_count,
            recorded_at=datetime.now(UTC),
        )

        cls._in_memory_feedback.append(feedback)

        if session is not None:
            now = datetime.now(UTC)
            record = CandidateFeedbackRecord(
                id=feedback.feedback_id,
                candidate_id=candidate.defense_id,
                evaluator_verdict=evaluation_result.verdict.value,
                evaluator_rationale=evaluation_result.verdict_rationale,
                detection_rate=evaluation_result.detection_rate,
                false_positive_rate=evaluation_result.false_positive_rate,
                regression_count=evaluation_result.regression_count,
                details={
                    "candidate_version": candidate.version,
                    "suite_id": evaluation_result.scenario_suite_id,
                    "passed_scenarios": evaluation_result.passed_scenarios,
                    "total_scenarios": evaluation_result.total_scenarios,
                    "rule_count": len(candidate.rule_spec.get("rules", [])),
                },
                created_at=now,
                updated_at=now,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)

        logger.info(
            f"Logged feedback for candidate {candidate.defense_id}: "
            f"verdict={feedback.evaluator_verdict.value}, regressions={feedback.regression_count}"
        )

        return feedback

    @classmethod
    async def get_feedback_for_candidate(
        cls,
        candidate_id: UUID,
        session: AsyncSession | None = None,
    ) -> list[CandidateFeedback]:
        """Retrieve feedback records for a specific candidate defense."""
        if session is not None:
            stmt = (
                select(CandidateFeedbackRecord)
                .where(CandidateFeedbackRecord.candidate_id == candidate_id)
                .order_by(CandidateFeedbackRecord.created_at.desc())
            )
            res = await session.execute(stmt)
            records = res.scalars().all()
            return [
                CandidateFeedback(
                    feedback_id=r.id,
                    candidate_id=r.candidate_id,
                    evaluator_verdict=EvaluationVerdict(r.evaluator_verdict),
                    evaluator_rationale=r.evaluator_rationale,
                    detection_rate=r.detection_rate,
                    false_positive_rate=r.false_positive_rate,
                    regression_count=r.regression_count,
                    recorded_at=r.created_at,
                )
                for r in records
            ]

        return [f for f in cls._in_memory_feedback if f.candidate_id == candidate_id]

    @classmethod
    async def get_rejected_categories(
        cls,
        session: AsyncSession | None = None,
    ) -> set[str]:
        """Return categories of candidates that failed evaluation due to regressions or high FPR."""
        # Query feedback with verdict == 'fail'
        rejected_categories: set[str] = set()
        if session is not None:
            stmt = select(CandidateFeedbackRecord).where(
                CandidateFeedbackRecord.evaluator_verdict == EvaluationVerdict.FAIL.value
            )
            res = await session.execute(stmt)
            for r in res.scalars().all():
                details = r.details or {}
                if "target_category" in details:
                    rejected_categories.add(details["target_category"])
        else:
            for f in cls._in_memory_feedback:
                if f.evaluator_verdict == EvaluationVerdict.FAIL:
                    pass

        return rejected_categories

    @classmethod
    async def get_learning_summary(
        cls,
        session: AsyncSession | None = None,
    ) -> dict[str, Any]:
        """Aggregate high-level learning metrics across all candidate evaluations."""
        if session is not None:
            stmt = select(CandidateFeedbackRecord)
            res = await session.execute(stmt)
            records = list(res.scalars().all())
            total = len(records)
            approved = sum(
                1 for r in records if r.evaluator_verdict == EvaluationVerdict.PASS.value
            )
            rejected = sum(
                1 for r in records if r.evaluator_verdict == EvaluationVerdict.FAIL.value
            )
            total_regressions = sum(r.regression_count for r in records)
            avg_fpr = (sum(r.false_positive_rate for r in records) / total) if total else 0.0
            avg_det = (sum(r.detection_rate for r in records) / total) if total else 0.0
        else:
            total = len(cls._in_memory_feedback)
            approved = sum(
                1 for f in cls._in_memory_feedback if f.evaluator_verdict == EvaluationVerdict.PASS
            )
            rejected = sum(
                1 for f in cls._in_memory_feedback if f.evaluator_verdict == EvaluationVerdict.FAIL
            )
            total_regressions = sum(f.regression_count for f in cls._in_memory_feedback)
            avg_fpr = (
                (sum(f.false_positive_rate for f in cls._in_memory_feedback) / total)
                if total
                else 0.0
            )
            avg_det = (
                (sum(f.detection_rate for f in cls._in_memory_feedback) / total) if total else 0.0
            )

        return {
            "total_feedbacks": total,
            "approved_candidates": approved,
            "rejected_candidates": rejected,
            "acceptance_rate": round(approved / total, 4) if total else 0.0,
            "total_regressions_observed": total_regressions,
            "average_candidate_fpr": round(avg_fpr, 4),
            "average_candidate_detection_rate": round(avg_det, 4),
        }
