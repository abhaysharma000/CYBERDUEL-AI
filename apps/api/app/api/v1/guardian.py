"""CyberDuel Guardian Supervisor API endpoints.

Exposes live agent monitoring, supervisory mission orchestration,
the CyberDuel Live Defense Challenge, and chronological activity audit trails.
"""

from __future__ import annotations

from uuid import UUID

from cyberduel_contracts.guardian import (
    GuardianActivityEvent,
    GuardianMissionContract,
    GuardianMissionRequest,
    GuardianStatusResponse,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.rate_limit import rate_limit_dependency
from apps.api.app.db.session import get_db_session
from apps.api.app.models.guardian import GuardianMissionRecord
from apps.api.app.services.guardian.supervisor import CyberDuelGuardian

router = APIRouter(
    prefix="/guardian",
    tags=["Guardian Supervisor"],
    dependencies=[Depends(rate_limit_dependency)],
)


@router.get("/status", response_model=GuardianStatusResponse)
async def get_guardian_status(
    session: AsyncSession = Depends(get_db_session),
) -> GuardianStatusResponse:
    """Discover real-time operational status, agent health, and active mission telemetry."""
    guardian = CyberDuelGuardian(session=session)
    return await guardian.get_status()


@router.get("/activity", response_model=list[GuardianActivityEvent])
async def get_guardian_activity(
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(default=30, ge=1, le=100),
) -> list[GuardianActivityEvent]:
    """Retrieve chronological activity timeline events recorded across Guardian operations."""
    guardian = CyberDuelGuardian(session=session)
    return await guardian.get_activity_timeline(limit=limit)


@router.post(
    "/missions",
    response_model=GuardianMissionContract,
    status_code=status.HTTP_201_CREATED,
)
async def trigger_guardian_mission(
    request: GuardianMissionRequest,
    session: AsyncSession = Depends(get_db_session),
) -> GuardianMissionContract:
    """Launch an autonomous supervised research-to-defense mission."""
    guardian = CyberDuelGuardian(session=session)
    return await guardian.execute_mission(request)


@router.post(
    "/challenge",
    response_model=GuardianMissionContract,
    status_code=status.HTTP_201_CREATED,
)
async def trigger_live_defense_challenge(
    session: AsyncSession = Depends(get_db_session),
) -> GuardianMissionContract:
    """Execute the authoritative 9-stage 'CyberDuel Live Defense Challenge'.

    Demonstrates continuous weakness discovery, Blue AI defense generation,
    Independent Evaluator verification, cryptographic signing, and verified client protection.
    """
    guardian = CyberDuelGuardian(session=session)
    return await guardian.execute_live_challenge()


@router.get("/missions", response_model=list[GuardianMissionContract])
async def list_guardian_missions(
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(default=20, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
) -> list[GuardianMissionContract]:
    """List historical Guardian missions with pagination."""
    stmt = (
        select(GuardianMissionRecord)
        .order_by(GuardianMissionRecord.started_at.desc())
        .offset(offset)
        .limit(limit)
    )
    records = (await session.execute(stmt)).scalars().all()
    guardian = CyberDuelGuardian(session=session)

    results: list[GuardianMissionContract] = []
    for rec in records:
        tl: list[GuardianActivityEvent] = []
        if isinstance(rec.timeline, list):
            for e in rec.timeline:
                try:
                    tl.append(GuardianActivityEvent(**e))
                except Exception:
                    continue
        results.append(guardian._to_contract(rec, tl))
    return results


@router.get("/missions/{mission_id}", response_model=GuardianMissionContract)
async def get_guardian_mission(
    mission_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> GuardianMissionContract:
    """Retrieve detailed state, decision reasoning, and activity timeline for a mission."""
    stmt = select(GuardianMissionRecord).where(GuardianMissionRecord.id == mission_id)
    rec = (await session.execute(stmt)).scalar_one_or_none()
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Guardian mission '{mission_id}' not found.",
        )

    guardian = CyberDuelGuardian(session=session)
    tl: list[GuardianActivityEvent] = []
    if isinstance(rec.timeline, list):
        for e in rec.timeline:
            try:
                tl.append(GuardianActivityEvent(**e))
            except Exception:
                continue
    return guardian._to_contract(rec, tl)
