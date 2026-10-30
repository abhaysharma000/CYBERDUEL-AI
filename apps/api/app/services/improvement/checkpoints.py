"""Checkpoint management and auditable progress persistence for self-improvement cycles."""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.evaluations import CycleCheckpointRecord

logger = logging.getLogger("improvement.checkpoints")


class CheckpointManager:
    """Records and retrieves step-by-step audit checkpoints during self-improvement execution."""

    @classmethod
    async def record_checkpoint(
        cls,
        session: AsyncSession,
        cycle_id: UUID,
        step_number: int,
        step_name: str,
        details: dict[str, Any] | None = None,
    ) -> CycleCheckpointRecord:
        """Persist a single step checkpoint within a cycle."""
        checkpoint = CycleCheckpointRecord(
            id=uuid4(),
            cycle_id=cycle_id,
            step_number=step_number,
            step_name=step_name,
            details=details or {},
            created_at=datetime.now(UTC),
        )
        session.add(checkpoint)
        await session.flush()
        logger.debug(
            f"Cycle {cycle_id} checkpoint #{step_number} [{step_name}] recorded: {list((details or {}).keys())}"
        )
        return checkpoint

    @classmethod
    async def get_checkpoints_for_cycle(
        cls,
        session: AsyncSession,
        cycle_id: UUID,
    ) -> list[CycleCheckpointRecord]:
        """Retrieve all recorded checkpoints for a given cycle in sequential order."""
        stmt = (
            select(CycleCheckpointRecord)
            .where(CycleCheckpointRecord.cycle_id == cycle_id)
            .order_by(CycleCheckpointRecord.step_number.asc())
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
