"""Domain model for incoming edge telemetry observations."""

from typing import Any

from sqlalchemy import JSON, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ThreatObservation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Telemetry report submitted by an edge client (browser or mobile).

    Note: An incoming observation is NOT treated as ground truth or proof of maliciousness.
    It is ingested in an unverified state for automated laboratory triage.
    """

    __tablename__ = "threat_observations"

    normalized_target: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
        doc="Normalized hash or anonymized indicator of interest",
    )
    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Client source: browser_extension, mobile_app, or feed",
    )
    local_action_taken: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        doc="Action taken locally by edge agent prior to submission: allow, warn, block",
    )
    engine_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="Version of edge engine that submitted the report",
    )
    policy_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="Active defensive policy installed on the client",
    )
    telemetry_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        doc="Privacy-minimized structural telemetry without sensitive user browsing data",
    )
    verification_status: Mapped[str] = mapped_column(
        String(32),
        default="unverified",
        nullable=False,
        index=True,
        doc="Lifecycle state: unverified, triaged, synthesized, benign_false_positive",
    )

    __table_args__ = (
        Index("ix_threat_obs_target_status", "normalized_target", "verification_status"),
    )
