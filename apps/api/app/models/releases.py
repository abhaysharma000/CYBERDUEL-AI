"""Database models for cryptographic signing keys, releases, authorizations, rollouts, and acknowledgements."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class SigningKeyRecord(Base, TimestampMixin):
    """Authority cryptographic signing keys for release manifest generation and verification."""

    __tablename__ = "signing_keys"

    key_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        doc="Unique identifier of the signing key (e.g. cyberduel-prod-2026-k1)",
    )
    algorithm: Mapped[str] = mapped_column(
        String(32),
        default="ed25519",
        nullable=False,
    )
    public_key_pem: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Public key in PEM format distributed to clients as trust anchor",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="active",
        nullable=False,
        index=True,
        doc="active, rotated, revoked",
    )
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revocation_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )


class ReleaseRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Cryptographically signed, immutable defensive policy release authorized for distribution."""

    __tablename__ = "releases"

    policy_version: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        nullable=False,
        index=True,
    )
    sequence_number: Mapped[int] = mapped_column(
        Integer,
        unique=True,
        nullable=False,
        index=True,
        doc="Monotonic sequence number for anti-replay",
    )
    channel: Mapped[str] = mapped_column(
        String(32),
        default="stable",
        nullable=False,
        index=True,
        doc="development, canary, stable, emergency",
    )
    candidate_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("candidate_defenses.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    evaluation_report_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evaluation_reports.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="draft",
        nullable=False,
        index=True,
        doc="draft, eligible, approved, staged, published, paused, revoked, rolled_back, superseded",
    )
    min_client_version: Mapped[str] = mapped_column(
        String(32),
        default="0.1.0",
        nullable=False,
    )
    max_client_version: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    min_engine_version: Mapped[str] = mapped_column(
        String(32),
        default="1.0.0",
        nullable=False,
    )
    supported_platforms: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    artifact_path: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        doc="Storage filesystem path to immutable policy bundle artifact",
    )
    artifact_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="SHA-256 hash of the canonical policy bundle",
    )
    artifact_size_bytes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    publisher_key_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("signing_keys.key_id"),
        nullable=False,
        index=True,
    )
    signature: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Ed25519 detached digital signature over canonical manifest bytes",
    )
    manifest_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    bundle_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        doc="In-memory/database copy of the declarative policy bundle",
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    is_mandatory: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    is_rollback: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    rollback_target_version: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    release_notes: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    authorizations: Mapped[list["ReleaseAuthorizationRecord"]] = relationship(
        back_populates="release",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    rollout_state: Mapped["RolloutStateRecord | None"] = relationship(
        back_populates="release",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    acknowledgements: Mapped[list["ClientAcknowledgementRecord"]] = relationship(
        back_populates="release",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_releases_channel_seq", "channel", "sequence_number"),
        Index("ix_releases_status_channel", "status", "channel"),
    )


class ReleaseAuthorizationRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Explicit administrative authorization record required for production deployment."""

    __tablename__ = "release_authorizations"

    release_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("releases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    evaluation_report_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    )
    policy_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    target_channel: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    authorized_by: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    rationale: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    authorized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    release: Mapped[ReleaseRecord] = relationship(
        back_populates="authorizations",
        lazy="selectin",
    )


class RolloutStateRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Rollout progression, cohort targeting, and stability metrics for a release."""

    __tablename__ = "rollout_states"

    release_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("releases.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    channel: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    stage: Mapped[str] = mapped_column(
        String(32),
        default="internal",
        nullable=False,
        index=True,
        doc="internal, canary_10, canary_25, canary_50, general_availability, paused, halted, rolled_back",
    )
    rollout_percentage: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )
    is_paused: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    total_targeted_clients: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    successful_installs: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    failed_installs: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    rollback_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    failure_rate: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )
    stage_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    release: Mapped[ReleaseRecord] = relationship(
        back_populates="rollout_state",
        lazy="selectin",
    )


class ClientDeviceRecord(Base, TimestampMixin):
    """Registered edge client device tracking version state and cohort allocation."""

    __tablename__ = "client_devices"

    client_id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
    )
    client_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    current_policy_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    current_sequence_number: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    engine_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    platform: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    channel: Mapped[str] = mapped_column(
        String(32),
        default="stable",
        nullable=False,
        index=True,
    )
    cohort_bucket: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        index=True,
        doc="Deterministic hash bucket (0-99) for staged rollouts",
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    acknowledgements: Mapped[list["ClientAcknowledgementRecord"]] = relationship(
        back_populates="client",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class ClientAcknowledgementRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Telemetry report recording whether a client successfully applied or failed an update."""

    __tablename__ = "client_acknowledgements"

    client_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("client_devices.client_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    release_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("releases.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    policy_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    sequence_number: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        doc="applied, failed, rolled_back",
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    client: Mapped[ClientDeviceRecord] = relationship(
        back_populates="acknowledgements",
        lazy="selectin",
    )
    release: Mapped[ReleaseRecord | None] = relationship(
        back_populates="acknowledgements",
        lazy="selectin",
    )
