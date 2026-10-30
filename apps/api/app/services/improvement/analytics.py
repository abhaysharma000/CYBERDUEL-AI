"""Analytics and trend tracking service across autonomous self-improvement cycles."""

import logging
from uuid import UUID

from cyberduel_contracts.enums import CycleStatus
from cyberduel_contracts.evaluation import (
    CycleCheckpoint,
    ImprovementCycleSummary,
    ImprovementTrendReport,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.evaluations import (
    CycleCheckpointRecord,
    ImprovementCycleRecord,
)

logger = logging.getLogger("improvement.analytics")


class ImprovementAnalyticsService:
    """Computes longitudinal performance metrics and status reports across improvement cycles."""

    @classmethod
    async def get_cycle_summary(
        cls,
        session: AsyncSession,
        cycle_id: UUID,
    ) -> ImprovementCycleSummary | None:
        """Fetch summary and checkpoints for a specific cycle."""
        stmt = select(ImprovementCycleRecord).where(ImprovementCycleRecord.id == cycle_id)
        result = await session.execute(stmt)
        record = result.scalar_one_or_none()
        if not record:
            return None

        chk_stmt = (
            select(CycleCheckpointRecord)
            .where(CycleCheckpointRecord.cycle_id == cycle_id)
            .order_by(CycleCheckpointRecord.step_number.asc())
        )
        chk_res = await session.execute(chk_stmt)
        checkpoints = [
            CycleCheckpoint(
                checkpoint_id=c.id,
                cycle_id=c.cycle_id,
                step_number=c.step_number,
                step_name=c.step_name,
                details=c.details,
                timestamp=c.created_at,
            )
            for c in chk_res.scalars().all()
        ]

        duration = 0.0
        if record.completed_at and record.started_at:
            duration = max(0.0, (record.completed_at - record.started_at).total_seconds())

        return ImprovementCycleSummary(
            cycle_id=record.id,
            cycle_number=record.cycle_number,
            status=CycleStatus(record.status),
            trigger_reason=record.trigger_reason,
            started_at=record.started_at,
            completed_at=record.completed_at,
            duration_seconds=round(duration, 2),
            findings_selected=len(record.selected_findings),
            hypotheses_formulated=record.summary_metrics.get("hypotheses_count", 0),
            candidates_generated=record.summary_metrics.get("candidates_generated", 0),
            candidates_evaluated=record.candidates_evaluated,
            accepted_candidate_id=record.accepted_candidate_id,
            accepted_candidate_version=record.accepted_candidate_version,
            terminal_reason=record.terminal_reason,
            budget_used_pct=record.summary_metrics.get("budget_used_pct", 0.0),
            checkpoints=checkpoints,
        )

    @classmethod
    async def list_cycles(
        cls,
        session: AsyncSession,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ImprovementCycleSummary]:
        """List historical self-improvement cycles with summaries."""
        stmt = (
            select(ImprovementCycleRecord)
            .order_by(ImprovementCycleRecord.cycle_number.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await session.execute(stmt)
        records = result.scalars().all()

        summaries: list[ImprovementCycleSummary] = []
        for r in records:
            duration = 0.0
            if r.completed_at and r.started_at:
                duration = max(0.0, (r.completed_at - r.started_at).total_seconds())
            summaries.append(
                ImprovementCycleSummary(
                    cycle_id=r.id,
                    cycle_number=r.cycle_number,
                    status=CycleStatus(r.status),
                    trigger_reason=r.trigger_reason,
                    started_at=r.started_at,
                    completed_at=r.completed_at,
                    duration_seconds=round(duration, 2),
                    findings_selected=len(r.selected_findings),
                    hypotheses_formulated=r.summary_metrics.get("hypotheses_count", 0),
                    candidates_generated=r.summary_metrics.get("candidates_generated", 0),
                    candidates_evaluated=r.candidates_evaluated,
                    accepted_candidate_id=r.accepted_candidate_id,
                    accepted_candidate_version=r.accepted_candidate_version,
                    terminal_reason=r.terminal_reason,
                    budget_used_pct=r.summary_metrics.get("budget_used_pct", 0.0),
                    checkpoints=[],
                )
            )
        return summaries

    @classmethod
    async def get_trend_report(
        cls,
        session: AsyncSession,
        limit: int = 20,
    ) -> ImprovementTrendReport:
        """Compute aggregate trend analytics across all completed improvement cycles."""
        history = await cls.list_cycles(session, limit=limit)
        total_cycles = len(history)
        if total_cycles == 0:
            return ImprovementTrendReport()

        successful = [c for c in history if c.accepted_candidate_id is not None]
        total_eval = sum(c.candidates_evaluated for c in history)
        accepted_count = len(successful)

        durations = [c.duration_seconds for c in history if c.duration_seconds > 0]
        mean_duration = round(sum(durations) / len(durations), 2) if durations else 0.0

        cumulative_resolved = sum(
            c.summary_metrics.get("failures_resolved", 0) if hasattr(c, "summary_metrics") else 0
            for c in history
        )

        return ImprovementTrendReport(
            total_cycles=total_cycles,
            successful_cycles=accepted_count,
            total_candidates_evaluated=total_eval,
            total_candidates_accepted=accepted_count,
            cumulative_failures_resolved=cumulative_resolved,
            mean_cycle_duration_seconds=mean_duration,
            cycle_history=history,
        )
