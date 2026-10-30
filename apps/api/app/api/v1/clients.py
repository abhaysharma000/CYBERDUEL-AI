"""Client fleet monitoring and telemetry endpoints for CyberDuel AI Command Center."""

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.app.core.auth import require_permission
from apps.api.app.db.session import get_db_session
from apps.api.app.models.releases import ClientAcknowledgementRecord, ClientDeviceRecord

router = APIRouter(prefix="/clients", tags=["Client Fleet Monitoring"])


class ClientSummary(BaseModel):
    """Client device summary for dashboard listings."""

    client_id: str
    client_type: str
    platform: str
    engine_version: str
    current_policy_version: str
    channel: str
    cohort_bucket: int
    last_seen_at: datetime
    acknowledgements_count: int = 0
    latest_status: str = "nominal"


class ClientMetrics(BaseModel):
    """Real client fleet metrics calculated from database state."""

    total_registered: int
    active_last_24h: int
    by_type: dict[str, int]
    by_channel: dict[str, int]
    by_policy_version: dict[str, int]
    acknowledgements_breakdown: dict[str, int]


@router.get(
    "",
    response_model=list[ClientSummary],
    dependencies=[Depends(require_permission("clients:read"))],
)
async def list_clients(
    client_type: str | None = None,
    channel: str | None = None,
    policy_version: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_db_session),
) -> list[ClientSummary]:
    """List registered browser and mobile client devices with real status."""
    stmt = select(ClientDeviceRecord).options(selectinload(ClientDeviceRecord.acknowledgements))
    if client_type:
        stmt = stmt.where(ClientDeviceRecord.client_type == client_type)
    if channel:
        stmt = stmt.where(ClientDeviceRecord.channel == channel)
    if policy_version:
        stmt = stmt.where(ClientDeviceRecord.current_policy_version == policy_version)

    stmt = stmt.order_by(desc(ClientDeviceRecord.last_seen_at)).offset(offset).limit(limit)
    res = await session.execute(stmt)
    devices = res.scalars().all()

    results: list[ClientSummary] = []
    for d in devices:
        ack_count = len(d.acknowledgements) if d.acknowledgements else 0
        latest_ack = d.acknowledgements[-1] if d.acknowledgements else None
        latest_status = "nominal"
        if latest_ack:
            if latest_ack.status == "failed":
                latest_status = "error"
            elif latest_ack.status == "rolled_back":
                latest_status = "rolled_back"
            elif latest_ack.status == "applied":
                latest_status = "updated"

        results.append(
            ClientSummary(
                client_id=d.client_id,
                client_type=d.client_type,
                platform=d.platform,
                engine_version=d.engine_version,
                current_policy_version=d.current_policy_version,
                channel=d.channel,
                cohort_bucket=d.cohort_bucket,
                last_seen_at=d.last_seen_at,
                acknowledgements_count=ack_count,
                latest_status=latest_status,
            )
        )
    return results


@router.get(
    "/metrics",
    response_model=ClientMetrics,
    dependencies=[Depends(require_permission("clients:read"))],
)
async def get_client_metrics(session: AsyncSession = Depends(get_db_session)) -> ClientMetrics:
    """Calculate aggregated fleet statistics directly from client tables."""
    now = datetime.now(UTC)
    cutoff = now - timedelta(hours=24)

    total_res = await session.execute(select(func.count(ClientDeviceRecord.client_id)))
    total = total_res.scalar() or 0

    active_res = await session.execute(
        select(func.count(ClientDeviceRecord.client_id)).where(
            ClientDeviceRecord.last_seen_at >= cutoff
        )
    )
    active_24h = active_res.scalar() or 0

    # By client_type
    type_res = await session.execute(
        select(ClientDeviceRecord.client_type, func.count(ClientDeviceRecord.client_id)).group_by(
            ClientDeviceRecord.client_type
        )
    )
    by_type = {row[0]: row[1] for row in type_res.all()}

    # By channel
    chan_res = await session.execute(
        select(ClientDeviceRecord.channel, func.count(ClientDeviceRecord.client_id)).group_by(
            ClientDeviceRecord.channel
        )
    )
    by_channel = {row[0]: row[1] for row in chan_res.all()}

    # By policy version
    pv_res = await session.execute(
        select(
            ClientDeviceRecord.current_policy_version, func.count(ClientDeviceRecord.client_id)
        ).group_by(ClientDeviceRecord.current_policy_version)
    )
    by_policy_version = {row[0]: row[1] for row in pv_res.all()}

    # Acknowledgements breakdown
    ack_res = await session.execute(
        select(
            ClientAcknowledgementRecord.status, func.count(ClientAcknowledgementRecord.id)
        ).group_by(ClientAcknowledgementRecord.status)
    )
    ack_breakdown = {row[0]: row[1] for row in ack_res.all()}

    return ClientMetrics(
        total_registered=total,
        active_last_24h=active_24h,
        by_type=by_type,
        by_channel=by_channel,
        by_policy_version=by_policy_version,
        acknowledgements_breakdown=ack_breakdown,
    )


@router.get("/{client_id}", dependencies=[Depends(require_permission("clients:read"))])
async def get_client_detail(
    client_id: str, session: AsyncSession = Depends(get_db_session)
) -> dict[str, Any]:
    """Retrieve full detail for a single client device."""
    stmt = (
        select(ClientDeviceRecord)
        .options(selectinload(ClientDeviceRecord.acknowledgements))
        .where(ClientDeviceRecord.client_id == client_id)
    )
    res = await session.execute(stmt)
    device = res.scalars().first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client '{client_id}' not found.",
        )

    acks = [
        {
            "id": str(a.id),
            "policy_version": a.policy_version,
            "sequence_number": a.sequence_number,
            "status": a.status,
            "error_message": a.error_message,
            "recorded_at": a.recorded_at.isoformat(),
        }
        for a in (device.acknowledgements or [])
    ]

    return {
        "client_id": device.client_id,
        "client_type": device.client_type,
        "platform": device.platform,
        "engine_version": device.engine_version,
        "current_policy_version": device.current_policy_version,
        "channel": device.channel,
        "cohort_bucket": device.cohort_bucket,
        "last_seen_at": device.last_seen_at.isoformat(),
        "acknowledgements": acks,
    }
