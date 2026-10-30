"""Evaluation handoff service for Blue AI.

Submits candidate defenses and evidence dossiers to the Independent Evaluation Engine,
enforcing strict boundary controls between defense proposition and release qualification.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from cyberduel_contracts.enums import DefenseStatus, EvaluationVerdict
from cyberduel_contracts.evaluation import EvaluationResult
from cyberduel_contracts.policy import CandidateDefense
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.lab import EvaluationRunRecord
from apps.api.app.models.policies import CandidateDefenseRecord
from services.evaluator.app.evaluator import BenchmarkEvaluator

logger = logging.getLogger("blue_ai.handoff")


class EvaluationHandoffService:
    """Submits candidate defenses to the Independent Evaluator and updates candidate status."""

    def __init__(self, evaluator: BenchmarkEvaluator | None = None) -> None:
        self.evaluator = evaluator or BenchmarkEvaluator()

    async def submit_candidate(
        self,
        candidate: CandidateDefense,
        suite_id: str = "curated-golden-v1",
        session: AsyncSession | None = None,
    ) -> EvaluationResult:
        """Submit candidate defense to independent benchmark evaluation."""
        logger.info(
            f"Handing off candidate {candidate.version} (ID: {candidate.defense_id}) "
            f"to independent benchmark evaluation on suite {suite_id}"
        )

        # Execute evaluation in independent evaluator service
        result = await self.evaluator.evaluate_candidate(
            candidate=candidate,
            suite_id=suite_id,
        )

        # Determine updated candidate status based strictly on the evaluator's verdict
        if result.verdict == EvaluationVerdict.PASS:
            new_status = DefenseStatus.APPROVED
        elif result.verdict == EvaluationVerdict.FAIL:
            new_status = DefenseStatus.REJECTED
        else:
            new_status = DefenseStatus.EVALUATING

        candidate.status = new_status

        # If a DB session is provided, persist the evaluation run and update candidate record
        if session is not None:
            now = datetime.now(UTC)
            eval_record = EvaluationRunRecord(
                id=result.evaluation_id,
                candidate_defense_id=candidate.defense_id,
                scenario_suite_id=suite_id,
                total_scenarios=result.total_scenarios,
                passed_scenarios=result.passed_scenarios,
                detection_rate=result.detection_rate,
                false_positive_rate=result.false_positive_rate,
                regression_count=result.regression_count,
                resource_overhead_ms=result.resource_overhead_ms,
                verdict=result.verdict.value,
                verdict_rationale=result.verdict_rationale,
                evaluated_at=now,
                created_at=now,
                updated_at=now,
            )
            session.add(eval_record)

            # Update candidate record status
            stmt = select(CandidateDefenseRecord).where(
                CandidateDefenseRecord.id == candidate.defense_id
            )
            c_res = await session.execute(stmt)
            c_record = c_res.scalar_one_or_none()
            if c_record:
                c_record.status = new_status.value
                c_record.updated_at = now

            await session.commit()

        logger.info(
            f"Independent evaluator returned {result.verdict.value.upper()} "
            f"for candidate {candidate.version}: {result.verdict_rationale}"
        )

        return result
