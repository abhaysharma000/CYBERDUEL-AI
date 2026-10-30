"""Autonomous Self-Improvement Controller REST API endpoints."""

from __future__ import annotations

import logging
from typing import Annotated, Any
from uuid import UUID

from cyberduel_contracts.enums import CycleStatus
from cyberduel_contracts.evaluation import (
    ImprovementCycleSummary,
    ImprovementTrendReport,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.db.session import get_db_session
from apps.api.app.models.evaluations import ImprovementCycleRecord
from apps.api.app.services.improvement.analytics import ImprovementAnalyticsService
from apps.api.app.services.improvement.controller import SelfImprovementController
from apps.api.app.services.improvement.policy import ControllerPolicyConfig

logger = logging.getLogger("api.improvement")
router = APIRouter(prefix="/improvement", tags=["Self-Improvement Controller"])


class StartCycleRequest(BaseModel):
    """Payload to launch an autonomous self-improvement cycle."""

    trigger_reason: str = Field(
        default="api_triggered_research",
        description="Reason or event that triggered this cycle",
    )
    max_candidates_per_cycle: int = Field(default=3, ge=1, le=10)
    cycle_timeout_seconds: float = Field(default=90.0, ge=10.0, le=300.0)
    benchmark_manifest_version: str = Field(default="benchmark-golden-v1")
    target_failure_categories: list[str] = Field(default_factory=list)


@router.post("/cycles", response_model=ImprovementCycleSummary, status_code=status.HTTP_201_CREATED)
async def start_improvement_cycle(
    payload: StartCycleRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ImprovementCycleSummary:
    """Launch an autonomous 10-step bounded self-improvement loop across Red AI, Blue AI, and Evaluator."""
    config = ControllerPolicyConfig(
        max_candidates_per_cycle=payload.max_candidates_per_cycle,
        cycle_timeout_seconds=payload.cycle_timeout_seconds,
        benchmark_manifest_version=payload.benchmark_manifest_version,
        target_failure_categories=payload.target_failure_categories,
    )
    controller = SelfImprovementController(session=session)
    summary = await controller.execute_cycle(config=config, trigger_reason=payload.trigger_reason)
    return summary


@router.get("/cycles", response_model=list[ImprovementCycleSummary])
async def list_improvement_cycles(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[ImprovementCycleSummary]:
    """List historical self-improvement cycles."""
    return await ImprovementAnalyticsService.list_cycles(session, limit=limit, offset=offset)


@router.get("/cycles/{cycle_id}", response_model=ImprovementCycleSummary)
async def get_cycle(
    cycle_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ImprovementCycleSummary:
    """Retrieve full summary and execution checkpoints for a specific cycle."""
    summary = await ImprovementAnalyticsService.get_cycle_summary(session, cycle_id)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Improvement cycle {cycle_id} not found",
        )
    return summary


@router.post("/cycles/{cycle_id}/cancel", response_model=dict[str, str])
async def cancel_cycle(
    cycle_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> dict[str, str]:
    """Cancel an active or running self-improvement cycle."""
    stmt = select(ImprovementCycleRecord).where(ImprovementCycleRecord.id == cycle_id)
    res = await session.execute(stmt)
    cycle = res.scalar_one_or_none()
    if not cycle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Improvement cycle {cycle_id} not found",
        )

    if cycle.status == CycleStatus.RUNNING.value:
        cycle.status = CycleStatus.CANCELLED.value
        cycle.terminal_reason = "Manually cancelled via API request"
        await session.commit()
        return {"status": "cancelled", "message": f"Cycle {cycle_id} cancelled"}

    return {"status": cycle.status, "message": f"Cycle is already {cycle.status}"}


@router.get("/history", response_model=ImprovementTrendReport)
async def get_trend_history(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    limit: int = Query(default=20, ge=1, le=100),
) -> ImprovementTrendReport:
    """Retrieve historical trend analytics, success rates, and cumulative failure resolutions."""
    return await ImprovementAnalyticsService.get_trend_report(session, limit=limit)


@router.get("/status")
async def get_controller_status(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> dict[str, Any]:
    """Retrieve current controller operational state and recent activity."""
    stmt_active = select(ImprovementCycleRecord).where(
        ImprovementCycleRecord.status == CycleStatus.RUNNING.value
    )
    res_active = await session.execute(stmt_active)
    active = res_active.scalars().all()

    stmt_recent = (
        select(ImprovementCycleRecord).order_by(ImprovementCycleRecord.cycle_number.desc()).limit(1)
    )
    res_recent = await session.execute(stmt_recent)
    latest = res_recent.scalar_one_or_none()

    return {
        "active_cycles_count": len(active),
        "is_busy": len(active) > 0,
        "latest_cycle_number": latest.cycle_number if latest else 0,
        "latest_cycle_status": latest.status if latest else "none",
        "latest_cycle_id": str(latest.id) if latest else None,
        "latest_accepted_candidate": latest.accepted_candidate_version if latest else None,
    }
