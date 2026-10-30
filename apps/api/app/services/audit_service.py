"""Audit logging service for operational and security event tracking."""

import logging
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.audit import AuditLogRecord

logger = logging.getLogger(__name__)


class AuditService:
    """Service for capturing and querying immutable audit events."""

    @staticmethod
    async def record_event(
        session: AsyncSession,
        actor: str,
        action: str,
        target_type: str,
        target_id: str | None = None,
        outcome: str = "success",
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
        client_ip: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditLogRecord:
        """Create and persist an immutable audit log record asynchronously."""
        record = AuditLogRecord(
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            reason=reason,
            metadata_json=metadata,
            client_ip=client_ip,
            correlation_id=correlation_id,
        )
        session.add(record)
        try:
            await session.commit()
            await session.refresh(record)
            logger.info("Audit event recorded: %s by %s [%s]", action, actor, outcome)
            return record
        except Exception as e:
            await session.rollback()
            logger.error("Failed to persist audit log: %s", e)
            raise

    @staticmethod
    async def query_events(
        session: AsyncSession,
        limit: int = 50,
        offset: int = 0,
        actor: str | None = None,
        action: str | None = None,
        target_type: str | None = None,
        outcome: str | None = None,
    ) -> tuple[list[AuditLogRecord], int]:
        """Query audit log records with filtering and pagination."""
        stmt = select(AuditLogRecord)
        count_stmt = select(func.count(AuditLogRecord.id))

        if actor:
            stmt = stmt.where(AuditLogRecord.actor == actor)
            count_stmt = count_stmt.where(AuditLogRecord.actor == actor)
        if action:
            stmt = stmt.where(AuditLogRecord.action.ilike(f"%{action}%"))
            count_stmt = count_stmt.where(AuditLogRecord.action.ilike(f"%{action}%"))
        if target_type:
            stmt = stmt.where(AuditLogRecord.target_type == target_type)
            count_stmt = count_stmt.where(AuditLogRecord.target_type == target_type)
        if outcome:
            stmt = stmt.where(AuditLogRecord.outcome == outcome)
            count_stmt = count_stmt.where(AuditLogRecord.outcome == outcome)

        total_res = await session.execute(count_stmt)
        total = total_res.scalar() or 0

        res = await session.execute(
            stmt.order_by(desc(AuditLogRecord.created_at))
            .offset(offset)
            .limit(min(limit, 200))
        )
        records = res.scalars().all()
        return list(records), total
