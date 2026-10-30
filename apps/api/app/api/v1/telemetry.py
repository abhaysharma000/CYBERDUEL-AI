"""Privacy-preserving edge telemetry ingestion and query endpoints."""

from typing import Any
from uuid import uuid4

from cyberduel_contracts.observation import ThreatObservationReport
from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.rate_limit import rate_limit_dependency
from apps.api.app.db.session import get_db_session
from apps.api.app.models.observations import ThreatObservation

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


class IngestionReceipt(BaseModel):
    receipt_id: str
    status: str
    message: str


@router.post(
    "/observations",
    response_model=IngestionReceipt,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Ingest Edge Observation Report",
    description="Accepts privacy-minimized edge telemetry for laboratory triage. Note: Unverified observations are never treated as automatic proof of maliciousness.",
)
async def ingest_observation(
    report: ThreatObservationReport,
    session: AsyncSession = Depends(get_db_session),
) -> IngestionReceipt:
    obs_id = report.observation_id or uuid4()
    obs = ThreatObservation(
        id=obs_id,
        normalized_target=report.normalized_target,
        source=report.source.value if hasattr(report.source, "value") else str(report.source),
        local_action_taken=report.local_action_taken.value
        if hasattr(report.local_action_taken, "value")
        else str(report.local_action_taken)
        if report.local_action_taken
        else None,
        engine_version=report.engine_version,
        policy_version=report.policy_version,
        telemetry_payload=report.telemetry_summary or {},
        verification_status="unverified",
    )
    session.add(obs)
    await session.commit()
    return IngestionReceipt(
        receipt_id=f"rec-{obs_id}",
        status="accepted_for_triage",
        message="Observation recorded for laboratory review.",
    )


@router.get(
    "/observations",
    summary="List Edge Observations",
    description="Returns recent edge telemetry observations submitted for laboratory triage.",
)
async def list_observations(
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(default=50, ge=1, le=100),
) -> list[dict[str, Any]]:
    stmt = select(ThreatObservation).order_by(ThreatObservation.created_at.desc()).limit(limit)
    res = await session.execute(stmt)
    records = res.scalars().all()
    return [
        {
            "id": str(r.id),
            "raw_url": (r.telemetry_payload or {}).get("raw_url", r.normalized_target),
            "redacted_url": (r.telemetry_payload or {}).get("redacted_url", r.normalized_target),
            "domain": (r.telemetry_payload or {}).get("domain", r.normalized_target),
            "decision": r.local_action_taken or "warn",
            "confidence_score": (r.telemetry_payload or {}).get("confidence_score", 0.9),
            "threat_types": (r.telemetry_payload or {}).get("threat_types", ["phishing"]),
            "source": r.source,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in records
    ]
