"""Domain models for device registrations and policy update deliveries."""

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from apps.api.app.models.policies import PolicyReleaseRecord


class DeviceRegistration(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Anonymous edge installation registration (browser extension or mobile device)."""

    __tablename__ = "device_registrations"

    client_id: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
    )
    client_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="browser_extension, mobile_app, or agent_node",
    )
    platform: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    engine_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    current_policy_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    update_deliveries: Mapped[list["UpdateDeliveryRecord"]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class UpdateDeliveryRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Tracking update dispatch and client acknowledgement status."""

    __tablename__ = "update_deliveries"

    device_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("device_registrations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    policy_release_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("policy_releases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="pending",
        nullable=False,
        index=True,
        doc="pending, delivered, applied, failed, rolled_back",
    )
    error_message: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    device: Mapped[DeviceRegistration] = relationship(
        back_populates="update_deliveries",
    )
    policy_release: Mapped["PolicyReleaseRecord"] = relationship(  # type: ignore[name-defined]
        back_populates="deliveries",
        lazy="selectin",
    )
