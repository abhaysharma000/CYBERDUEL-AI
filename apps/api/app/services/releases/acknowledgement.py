"""Processes client update telemetry, tracks deployment success/failure, and enforces circuit breakers."""

from datetime import UTC, datetime
from uuid import UUID

from cyberduel_contracts.updates import UpdateAcknowledgement
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.releases import (
    ClientAcknowledgementRecord,
    ClientDeviceRecord,
    ReleaseRecord,
    RolloutStateRecord,
)
from apps.api.app.services.releases.rollout import RolloutManager


class ClientAcknowledgementService:
    """Records update application results and automatically halts unstable rollouts."""

    def __init__(self, rollout_manager: RolloutManager | None = None) -> None:
        self.rollout_manager = rollout_manager or RolloutManager()

    async def record_acknowledgement(
        self,
        session: AsyncSession,
        ack: UpdateAcknowledgement,
    ) -> ClientAcknowledgementRecord:
        """Process client acknowledgement receipt, update device version state, and check safety thresholds."""
        now = datetime.now(UTC)
        try:
            # 1. Fetch matching release if available
            rel_stmt = select(ReleaseRecord).where(
                ReleaseRecord.policy_version == ack.policy_version
            )
            rel_result = await session.execute(rel_stmt)
            release = rel_result.scalar_one_or_none()

            release_id: UUID | None = release.id if release else None
            sequence_num = ack.sequence_number or (release.sequence_number if release else None)

            # 2. Update Client Device state
            client_stmt = select(ClientDeviceRecord).where(
                ClientDeviceRecord.client_id == ack.client_id
            )
            client = (await session.execute(client_stmt)).scalar_one_or_none()

            if client:
                client.last_seen_at = now
                if ack.status == "applied":
                    client.current_policy_version = ack.policy_version
                    if sequence_num is not None:
                        client.current_sequence_number = max(
                            client.current_sequence_number, sequence_num
                        )

            # 3. Update Rollout State Metrics
            if release:
                rollout_stmt = select(RolloutStateRecord).where(
                    RolloutStateRecord.release_id == release.id
                )
                rollout = (await session.execute(rollout_stmt)).scalar_one_or_none()
                if rollout:
                    rollout.total_targeted_clients += 1
                    if ack.status == "applied":
                        rollout.successful_installs += 1
                    elif ack.status == "failed":
                        rollout.failed_installs += 1
                    elif ack.status == "rolled_back":
                        rollout.rollback_count += 1

                    # Recalculate failure rate
                    total = rollout.successful_installs + rollout.failed_installs
                    if total > 0:
                        rollout.failure_rate = rollout.failed_installs / total

                    # Evaluate circuit breaker
                    self.rollout_manager.evaluate_circuit_breaker(rollout)
                    rollout.stage_updated_at = now

            # 4. Record Acknowledgement Entry
            ack_record = ClientAcknowledgementRecord(
                id=ack.acknowledgement_id,
                client_id=ack.client_id,
                release_id=release_id,
                policy_version=ack.policy_version,
                sequence_number=sequence_num,
                status=ack.status,
                error_message=ack.error_message,
                recorded_at=now,
            )
            session.add(ack_record)
            await session.flush()
            return ack_record
        except Exception:
            return ClientAcknowledgementRecord(
                id=ack.acknowledgement_id,
                client_id=ack.client_id,
                release_id=None,
                policy_version=ack.policy_version,
                sequence_number=ack.sequence_number,
                status=ack.status,
                error_message=ack.error_message,
                recorded_at=now,
            )
