"""Domain models for persistent threat analysis results and detection outcomes."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ThreatAnalysisRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Immutable audit record of a cloud threat analysis evaluation."""

    __tablename__ = "threat_analyses"

    normalized_identifier: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
    )
    threat_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        doc="Calibrated threat score from 0.0 (benign) to 1.0 (critical threat)",
    )
    decision: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        doc="Enacted verdict: allow, warn, or block",
    )
    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    provenance: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="local_rule, model_inference, or cloud_analysis",
    )
    engine_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    policy_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    evidence_payload: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    outcomes: Mapped[list["DetectionOutcomeRecord"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (Index("ix_threat_analyses_lookup", "normalized_identifier", "decision"),)


class DetectionOutcomeRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Enforcement outcome or client interaction logged after a threat analysis."""

    __tablename__ = "detection_outcomes"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("threat_analyses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    client_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
    )
    client_action_taken: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="Client reaction: e.g. blocked, user_override, ignored, warn_dismissed",
    )
    outcome_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    analysis: Mapped[ThreatAnalysisRecord] = relationship(
        back_populates="outcomes",
        lazy="selectin",
    )
