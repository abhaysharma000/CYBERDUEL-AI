"""Database model for immutable security audit logging."""

import uuid
from typing import Any

from sqlalchemy import JSON, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AuditLogRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Immutable audit log record for operational, research, and release events."""

    __tablename__ = "audit_log_records"

    event_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: f"aud_{uuid.uuid4().hex[:16]}",
    )
    actor: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    target_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    target_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
    )
    outcome: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="success",
    )
    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    client_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    correlation_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    __table_args__ = (
        Index("ix_audit_actor_created", "actor", "created_at"),
        Index("ix_audit_action_created", "action", "created_at"),
    )

