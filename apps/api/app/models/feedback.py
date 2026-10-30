"""Domain model for user and client feedback on detection accuracy."""

import uuid

from sqlalchemy import (
    ForeignKey,
    Index,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class FeedbackSubmission(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Privacy-conscious user feedback report (e.g. reporting a false positive block)."""

    __tablename__ = "feedback_submissions"

    feedback_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        doc="false_positive, false_negative, or general_feedback",
    )
    normalized_identifier: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
        doc="Privacy-preserving hash of the disputed resource",
    )
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("threat_analyses.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    user_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="Voluntary user context; sanitized to prevent ingestion of sensitive credentials",
    )
    triage_status: Mapped[str] = mapped_column(
        String(32),
        default="pending",
        nullable=False,
        index=True,
        doc="pending, reviewing, validated, or dismissed",
    )

    __table_args__ = (Index("ix_feedback_type_status", "feedback_type", "triage_status"),)
