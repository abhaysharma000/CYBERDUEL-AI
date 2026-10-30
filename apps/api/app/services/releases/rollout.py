"""Multi-channel staged rollout management, cohort allocation, progression, and safety circuit-breakers."""

import hashlib
from datetime import UTC, datetime
from uuid import UUID

from cyberduel_contracts.enums import (
    ReleaseChannel,
    ReleaseStatus,
    RolloutStage,
)
from cyberduel_contracts.releases import RolloutState
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.releases import ReleaseRecord, RolloutStateRecord

STAGE_PERCENTAGES: dict[RolloutStage, float] = {
    RolloutStage.INTERNAL: 0.0,
    RolloutStage.CANARY_10: 10.0,
    RolloutStage.CANARY_25: 25.0,
    RolloutStage.CANARY_50: 50.0,
    RolloutStage.GENERAL_AVAILABILITY: 100.0,
}

PROGRESSION_ORDER: list[RolloutStage] = [
    RolloutStage.INTERNAL,
    RolloutStage.CANARY_10,
    RolloutStage.CANARY_25,
    RolloutStage.CANARY_50,
    RolloutStage.GENERAL_AVAILABILITY,
]


class RolloutManager:
    """Controls staged release advancement, client cohort hash bucketing, and automated safety stops."""

    CIRCUIT_BREAKER_MAX_FAILURE_RATE = 0.05  # 5% maximum permissible install failure rate
    CIRCUIT_BREAKER_MIN_OBSERVATIONS = 10  # Minimum attempts before circuit-breaker can trip

    @staticmethod
    def get_cohort_bucket(client_id: str) -> int:
        """Deterministic hash bucket (0-99) for stable cohort allocation across versions."""
        digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()
        return int(digest[:8], 16) % 100

    @classmethod
    def is_client_in_rollout(cls, client_id: str, rollout_percentage: float) -> bool:
        """Evaluate if client is in the current target percentage cohort."""
        if rollout_percentage <= 0.0:
            return False
        if rollout_percentage >= 100.0:
            return True
        bucket = cls.get_cohort_bucket(client_id)
        return bucket < rollout_percentage

    async def advance_stage(
        self,
        session: AsyncSession,
        release_id: UUID,
        target_stage: RolloutStage | None = None,
    ) -> RolloutState:
        """Advance release rollout to the next stage or a specified target stage."""
        stmt = select(RolloutStateRecord).where(RolloutStateRecord.release_id == release_id)
        rollout_record = (await session.execute(stmt)).scalar_one_or_none()
        if not rollout_record:
            raise ValueError(f"No rollout state found for release '{release_id}'")

        rel_stmt = select(ReleaseRecord).where(ReleaseRecord.id == release_id)
        release_record = (await session.execute(rel_stmt)).scalar_one_or_none()
        if not release_record:
            raise ValueError(f"Release '{release_id}' not found")

        current_stage = RolloutStage(rollout_record.stage)
        if target_stage is None:
            try:
                current_idx = PROGRESSION_ORDER.index(current_stage)
                if current_idx < len(PROGRESSION_ORDER) - 1:
                    next_stage = PROGRESSION_ORDER[current_idx + 1]
                else:
                    next_stage = RolloutStage.GENERAL_AVAILABILITY
            except ValueError:
                next_stage = RolloutStage.CANARY_10
        else:
            next_stage = target_stage

        new_percentage = STAGE_PERCENTAGES.get(next_stage, 100.0)
        rollout_record.stage = next_stage.value
        rollout_record.rollout_percentage = new_percentage
        rollout_record.is_paused = False
        rollout_record.stage_updated_at = datetime.now(UTC)

        # If release was in approved or staged state, transition to published
        if release_record.status in (
            ReleaseStatus.APPROVED.value,
            ReleaseStatus.STAGED.value,
            ReleaseStatus.PAUSED.value,
        ):
            release_record.status = ReleaseStatus.PUBLISHED.value
            if not release_record.published_at:
                release_record.published_at = datetime.now(UTC)

        # If reaching General Availability, mark older releases in the same channel as superseded
        if next_stage == RolloutStage.GENERAL_AVAILABILITY:
            older_stmt = select(ReleaseRecord).where(
                ReleaseRecord.channel == release_record.channel,
                ReleaseRecord.id != release_record.id,
                ReleaseRecord.sequence_number < release_record.sequence_number,
                ReleaseRecord.status == ReleaseStatus.PUBLISHED.value,
            )
            older_records = (await session.execute(older_stmt)).scalars().all()
            for old in older_records:
                old.status = ReleaseStatus.SUPERSEDED.value

        await session.flush()
        return self._to_contract(rollout_record)

    async def pause_rollout(self, session: AsyncSession, release_id: UUID) -> RolloutState:
        """Pause a release rollout, halting further client update delivery."""
        stmt = select(RolloutStateRecord).where(RolloutStateRecord.release_id == release_id)
        record = (await session.execute(stmt)).scalar_one_or_none()
        if not record:
            raise ValueError(f"Rollout state not found for release '{release_id}'")

        rel_stmt = select(ReleaseRecord).where(ReleaseRecord.id == release_id)
        release = (await session.execute(rel_stmt)).scalar_one_or_none()

        record.is_paused = True
        record.stage_updated_at = datetime.now(UTC)
        if release:
            release.status = ReleaseStatus.PAUSED.value

        await session.flush()
        return self._to_contract(record)

    async def resume_rollout(self, session: AsyncSession, release_id: UUID) -> RolloutState:
        """Resume a paused release rollout."""
        stmt = select(RolloutStateRecord).where(RolloutStateRecord.release_id == release_id)
        record = (await session.execute(stmt)).scalar_one_or_none()
        if not record:
            raise ValueError(f"Rollout state not found for release '{release_id}'")

        rel_stmt = select(ReleaseRecord).where(ReleaseRecord.id == release_id)
        release = (await session.execute(rel_stmt)).scalar_one_or_none()

        record.is_paused = False
        record.stage_updated_at = datetime.now(UTC)
        if release and release.status == ReleaseStatus.PAUSED.value:
            release.status = ReleaseStatus.PUBLISHED.value

        await session.flush()
        return self._to_contract(record)

    def evaluate_circuit_breaker(self, rollout_record: RolloutStateRecord) -> bool:
        """Check if error rates trip automated safety halt thresholds. Returns True if tripped."""
        total = rollout_record.successful_installs + rollout_record.failed_installs
        if total >= self.CIRCUIT_BREAKER_MIN_OBSERVATIONS:
            failure_rate = rollout_record.failed_installs / total
            rollout_record.failure_rate = failure_rate
            if failure_rate > self.CIRCUIT_BREAKER_MAX_FAILURE_RATE:
                rollout_record.is_paused = True
                rollout_record.stage = RolloutStage.HALTED.value
                rollout_record.stage_updated_at = datetime.now(UTC)
                return True
        return False

    def _to_contract(self, record: RolloutStateRecord) -> RolloutState:
        return RolloutState(
            release_id=record.release_id,
            channel=ReleaseChannel(record.channel),
            stage=RolloutStage(record.stage),
            rollout_percentage=record.rollout_percentage,
            is_paused=record.is_paused,
            total_targeted_clients=record.total_targeted_clients,
            successful_installs=record.successful_installs,
            failed_installs=record.failed_installs,
            rollback_count=record.rollback_count,
            failure_rate=record.failure_rate,
            updated_at=record.stage_updated_at,
        )
