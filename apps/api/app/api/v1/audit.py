"""Audit log query endpoints for CyberDuel AI Command Center."""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.auth import require_permission
from apps.api.app.db.session import get_db_session
from apps.api.app.services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["Security Audit Trail"])


class AuditEventResponse(BaseModel):
    """Immutable audit record representation."""

    event_id: str
    actor: str
    action: str
    target_type: str
    target_id: str | None = None
    outcome: str
    reason: str | None = None
    metadata: dict[str, Any] | None = None
    client_ip: str | None = None
    correlation_id: str | None = None
    created_at: datetime


class AuditQueryResponse(BaseModel):
    """Paginated audit query response."""

    events: list[AuditEventResponse]
    total: int
    limit: int
    offset: int


@router.get(
    "/events",
    response_model=AuditQueryResponse,
    dependencies=[Depends(require_permission("audit:read"))],
)
async def list_audit_events(
    actor: str | None = None,
    action: str | None = None,
    target_type: str | None = None,
    outcome: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_db_session),
) -> AuditQueryResponse:
    """Retrieve filtered, immutable audit log events."""
    records, total = await AuditService.query_events(
        session=session,
        limit=limit,
        offset=offset,
        actor=actor,
        action=action,
        target_type=target_type,
        outcome=outcome,
    )

    items = [
        AuditEventResponse(
            event_id=r.event_id,
            actor=r.actor,
            action=r.action,
            target_type=r.target_type,
            target_id=r.target_id,
            outcome=r.outcome,
            reason=r.reason,
            metadata=r.metadata_json,
            client_ip=r.client_ip,
            correlation_id=r.correlation_id,
            created_at=r.created_at,
        )
        for r in records
    ]

    return AuditQueryResponse(
        events=items,
        total=total,
        limit=limit,
        offset=offset,
    )
