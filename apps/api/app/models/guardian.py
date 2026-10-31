"""SQLAlchemy ORM models for CyberDuel Guardian supervisor missions and timeline."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

JSONType = JSON().with_variant(JSONB, "postgresql")


class GuardianMissionRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Persisted record of an autonomous Guardian supervised mission or live challenge."""

    __tablename__ = "guardian_missions"

    mission_name: Mapped[str] = mapped_column(String(255), nullable=False)
    goal: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(64), nullable=False, default="idle", index=True)
    trigger_source: Mapped[str] = mapped_column(String(64), nullable=False, default="manual")

    experiment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("lab_experiments.id", ondelete="SET NULL"), nullable=True
    )
    candidate_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("candidate_defenses.id", ondelete="SET NULL"), nullable=True
    )
    candidate_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evaluation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("evaluation_reports.id", ondelete="SET NULL"), nullable=True
    )
    release_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("policy_releases.id", ondelete="SET NULL"), nullable=True
    )
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    initial_threat_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    initial_decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    final_decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    benign_control_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    benign_control_decision: Mapped[str | None] = mapped_column(String(32), nullable=True)

    decision_explanation: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    timeline: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, nullable=False, default=list)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terminal_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_guardian_missions_state_created", "state", "created_at"),
    )
