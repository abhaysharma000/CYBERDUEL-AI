"""Schemas for privacy-preserving threat observation reports from client edge devices."""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from cyberduel_contracts.enums import Decision, ObservationSource


class ThreatObservationReport(BaseModel):
    """Telemetry report submitted by an edge client encountering suspicious behavior."""

    model_config = ConfigDict(extra="forbid")

    observation_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this telemetry report",
    )
    source: ObservationSource = Field(
        ...,
        description="Origin of the report: browser_extension, mobile_app, or lab_scenario",
    )
    normalized_target: Annotated[
        str,
        Field(
            min_length=8,
            max_length=256,
            description="Cryptographic hash or canonicalized domain; raw URLs with user tokens are forbidden",
        ),
    ]
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the indicator was encountered",
    )
    local_action_taken: Decision | None = Field(
        default=None,
        description="Immediate decision enacted locally by the edge client prior to cloud submission",
    )
    engine_version: Annotated[
        str,
        Field(min_length=1, max_length=32, description="Client engine version at observation time"),
    ]
    policy_version: Annotated[
        str,
        Field(
            min_length=1,
            max_length=32,
            description="Client policy version active during observation",
        ),
    ]
    telemetry_summary: dict[str, Any] = Field(
        default_factory=dict,
        description="Privacy-minimized structural metadata (e.g. DOM structure flags, certificate features)",
    )
