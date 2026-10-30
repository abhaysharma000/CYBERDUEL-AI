"""Service for managing privacy-conscious threat observations and triage status."""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID, uuid4

from cyberduel_contracts.observation import ThreatObservationReport
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.observations import ThreatObservation

logger = logging.getLogger("observation_service")

# Permitted lifecycle status transitions
VALID_STATUS_TRANSITIONS = {
    "received": {"queued", "rejected"},
    "queued": {"investigating", "rejected"},
    "investigating": {"confirmed", "rejected", "needs_review"},
    "needs_review": {"investigating", "confirmed", "rejected"},
    "confirmed": set(),  # Terminal state
    "rejected": set(),  # Terminal state
}


class ThreatObservationService:
    """Handles edge report ingestion, status transitions, and privacy preservation."""

    def __init__(self, session: AsyncSession | None = None) -> None:
        self.session = session

    async def ingest_observation(
        self,
        report: ThreatObservationReport,
    ) -> dict[str, Any]:
        """Ingest and record a privacy-minimized threat observation."""
        # Sanitize telemetry summary to ensure no cleartext passwords/keys leak
        sanitized_summary = {
            k: v
            for k, v in report.telemetry_summary.items()
            if k.lower() not in {"password", "secret", "token", "auth", "key"}
        }

        observation_id = report.observation_id or uuid4()

        if self.session is not None:
            # Check for duplicate observation for the same normalized target within 1 hour
            stmt = select(ThreatObservation).where(
                ThreatObservation.normalized_target == report.normalized_target,
                ThreatObservation.source == report.source.value,
            )
            existing = (await self.session.execute(stmt)).scalars().first()
            if existing:
                return {
                    "observation_id": str(existing.id),
                    "status": existing.verification_status,
                    "duplicate": True,
                    "message": "Observation already recorded for this indicator.",
                }

            db_obs = ThreatObservation(
                id=observation_id,
                normalized_target=report.normalized_target,
                source=report.source.value,
                local_action_taken=report.local_action_taken.value
                if report.local_action_taken
                else None,
                engine_version=report.engine_version,
                policy_version=report.policy_version,
                telemetry_payload=sanitized_summary,
                verification_status="received",
            )
            self.session.add(db_obs)
            await self.session.commit()

        return {
            "observation_id": str(observation_id),
            "status": "received",
            "duplicate": False,
            "message": "Observation accepted and queued for laboratory triage.",
        }

    async def transition_status(
        self,
        observation_id: UUID,
        new_status: str,
    ) -> bool:
        """Update investigation status adhering to lifecycle transition rules."""
        if self.session is None:
            return False

        stmt = select(ThreatObservation).where(ThreatObservation.id == observation_id)
        obs = (await self.session.execute(stmt)).scalar_one_or_none()
        if not obs:
            return False

        current_status = obs.verification_status
        allowed_next = VALID_STATUS_TRANSITIONS.get(current_status, set())
        if new_status not in allowed_next:
            raise ValueError(
                f"Invalid status transition from '{current_status}' to '{new_status}'. "
                f"Allowed transitions: {list(allowed_next)}"
            )

        obs.verification_status = new_status
        await self.session.commit()
        return True
