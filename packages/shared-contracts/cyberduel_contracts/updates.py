"""Schemas for edge client update negotiation, verification, and roll-out status."""

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from cyberduel_contracts.enums import ReleaseChannel


class UpdateCheckRequest(BaseModel):
    """Payload sent by an edge client inquiring if new defensive policies are released."""

    model_config = ConfigDict(extra="forbid")

    client_id: Annotated[
        str,
        Field(min_length=8, max_length=128, description="Unique anonymous client installation ID"),
    ]
    client_type: Literal["browser_extension", "mobile_app", "agent_node"] = Field(
        ...,
        description="Type of client requesting the update",
    )
    current_policy_version: Annotated[
        str,
        Field(min_length=1, max_length=32, description="Currently installed policy version"),
    ]
    engine_version: Annotated[
        str,
        Field(min_length=1, max_length=32, description="Active local engine execution version"),
    ]
    platform: Annotated[
        str,
        Field(
            min_length=2,
            max_length=64,
            description="Host platform (e.g. Chrome-130, Android-15, Firefox-132)",
        ),
    ]
    channel: ReleaseChannel = Field(
        default=ReleaseChannel.STABLE,
        description="Release channel subscribed by this client (e.g. stable, canary)",
    )
    current_sequence_number: Annotated[
        int,
        Field(default=0, ge=0, description="Highest monotonic sequence number client has applied"),
    ] = 0


class UpdateCheckResponse(BaseModel):
    """Response specifying whether an approved update is pending installation."""

    model_config = ConfigDict(extra="forbid")

    update_available: bool = Field(
        ...,
        description="True if a newer validated policy exists for this client version",
    )
    target_version: Annotated[str | None, Field(default=None, max_length=32)] = None
    manifest_url: Annotated[str | None, Field(default=None, max_length=2048)] = None
    rules_digest: Annotated[str | None, Field(default=None, max_length=64)] = None
    signature: Annotated[str | None, Field(default=None, max_length=1024)] = None
    mandatory: bool = Field(
        default=False,
        description="If True, previous version is revoked or vulnerable and update is required",
    )
    sequence_number: int | None = Field(
        default=None,
        description="Sequence number of the target release",
    )
    release_id: UUID | None = Field(
        default=None,
        description="Unique identifier of the target release",
    )
    is_rollback: bool = Field(
        default=False,
        description="True if this update is a designated rollback action",
    )
    rollback_target_version: str | None = Field(
        default=None,
        description="If rollback, version string to roll back to",
    )


class UpdateAcknowledgement(BaseModel):
    """Receipt acknowledging the installation, failure, or rollback of a policy update."""

    model_config = ConfigDict(extra="forbid")

    acknowledgement_id: UUID = Field(
        default_factory=uuid4,
    )
    client_id: Annotated[
        str,
        Field(min_length=8, max_length=128, description="Client installation identifier"),
    ]
    policy_version: Annotated[
        str,
        Field(min_length=1, max_length=32, description="The policy version attempted"),
    ]
    status: Literal["applied", "failed", "rolled_back"] = Field(
        ...,
        description="Terminal outcome of the client update procedure",
    )
    error_message: Annotated[str | None, Field(default=None, max_length=512)] = None
    applied_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    sequence_number: int | None = Field(
        default=None,
        description="Sequence number attempted",
    )
