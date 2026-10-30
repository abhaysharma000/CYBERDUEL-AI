"""Domain model for persistent threat intelligence indicators."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    Index,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ThreatIndicatorRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Verified or provisional threat intelligence indicator (URL, domain, or IP)."""

    __tablename__ = "threat_indicators"

    indicator_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        doc="Type of indicator: url, domain, ip, or sha256",
    )
    normalized_value: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        index=True,
        doc="Canonical normalized string representation",
    )
    value_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="SHA-256 digest of normalized_value for fast exact-match lookup",
    )
    classification: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Threat class: phishing, malware, scam, c2, or benign",
    )
    source: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Originating feed or publisher",
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        default="high",
        nullable=False,
        doc="none, low, medium, high, or critical",
    )
    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        doc="Source-reported confidence score in [0.0, 1.0]",
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    source_version: Mapped[str] = mapped_column(
        String(32),
        default="1.0.0",
        nullable=False,
    )
    verification_status: Mapped[str] = mapped_column(
        String(32),
        default="verified",
        nullable=False,
        index=True,
        doc="verified, provisional, or revoked",
    )
    metadata_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    __table_args__ = (
        Index("ix_threat_indicators_hash_status", "value_hash", "verification_status"),
        Index("ix_threat_indicators_type_val", "indicator_type", "normalized_value"),
    )
