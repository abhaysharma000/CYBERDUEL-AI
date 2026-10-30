"""Data contracts for signed security updates, releases, rollouts, and client verification."""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from cyberduel_contracts.crypto import compute_canonical_sha256
from cyberduel_contracts.enums import (
    KeyStatus,
    ReleaseChannel,
    ReleaseStatus,
    RolloutStage,
)
from cyberduel_contracts.policy import DeclarativeRuleModel


class LocalProtectionPolicyBundle(BaseModel):
    """Complete, self-contained, declarative security policy and threat intelligence bundle.

    Contains strictly declarative definitions (no executable code or scripts).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    bundle_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this policy bundle",
    )
    policy_version: Annotated[
        str,
        Field(min_length=3, max_length=32, description="Semantic version string, e.g. '2026.10.2'"),
    ]
    sequence_number: Annotated[
        int,
        Field(ge=1, description="Strictly monotonic sequence number for anti-replay protection"),
    ]
    scoring_thresholds: dict[str, float] = Field(
        default_factory=lambda: {"warn_threshold": 0.50, "block_threshold": 0.85},
        description="Confidence thresholds for local risk assessment",
    )
    rules: list[DeclarativeRuleModel] = Field(
        default_factory=list,
        description="Declarative AST rules evaluated locally",
    )
    threat_indicators: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Known indicators, prefixes, and exact hashes (no executable logic)",
    )
    feature_weights: dict[str, float] = Field(
        default_factory=dict,
        description="Tuned model feature weights for client-side scoring",
    )
    schema_version: Annotated[
        str,
        Field(
            default="1.0.0", max_length=16, description="Policy bundle schema specification version"
        ),
    ]
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    expires_at: datetime = Field(
        ...,
        description="Staleness cutoff after which clients must refresh",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Provenance and build metadata",
    )

    def compute_digest(self) -> str:
        """Compute the canonical SHA-256 digest of this policy bundle."""
        return compute_canonical_sha256(self.model_dump(mode="json"))


class ReleaseManifest(BaseModel):
    """Cryptographically signed release manifest describing an update artifact for client distribution."""

    model_config = ConfigDict(extra="forbid")

    release_id: UUID = Field(
        default_factory=uuid4,
        description="Unique publication ID for this release",
    )
    policy_version: Annotated[
        str,
        Field(min_length=3, max_length=32, description="Target policy version, e.g. '2026.10.2'"),
    ]
    sequence_number: Annotated[
        int,
        Field(ge=1, description="Strictly monotonic sequence number across all releases"),
    ]
    channel: ReleaseChannel = Field(
        default=ReleaseChannel.STABLE,
        description="Release distribution channel",
    )
    status: ReleaseStatus = Field(
        default=ReleaseStatus.PUBLISHED,
        description="Current publication state",
    )
    published_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    expires_at: datetime = Field(
        ...,
        description="Timestamp after which clients must consider this release expired",
    )
    min_client_version: Annotated[
        str,
        Field(
            min_length=1, max_length=32, description="Minimum compatible client application version"
        ),
    ] = "0.1.0"
    max_client_version: Annotated[str | None, Field(default=None, max_length=32)] = None
    min_engine_version: Annotated[
        str,
        Field(min_length=1, max_length=32, description="Minimum detection engine version required"),
    ] = "1.0.0"
    supported_platforms: list[str] = Field(
        default_factory=lambda: ["browser_extension", "mobile_app", "agent_node"],
        description="Client platforms supported by this release",
    )
    artifact_digest: Annotated[
        str,
        Field(
            min_length=64,
            max_length=64,
            pattern=r"^[a-fA-F0-9]{64}$",
            description="SHA-256 digest of the canonical policy bundle",
        ),
    ]
    artifact_size_bytes: Annotated[
        int,
        Field(ge=1, description="Exact byte size of the artifact"),
    ]
    artifact_url: Annotated[
        str,
        Field(
            min_length=1,
            max_length=2048,
            description="URL or relative endpoint to download the artifact",
        ),
    ]
    publisher_key_id: Annotated[
        str,
        Field(min_length=4, max_length=64, description="Identifier of the authorized signing key"),
    ]
    signature: Annotated[
        str,
        Field(
            min_length=64,
            max_length=512,
            description="Detached Ed25519 signature over the canonical manifest",
        ),
    ]
    is_mandatory: bool = Field(
        default=False,
        description="If True, previous versions are deprecated or compromised and update is required",
    )
    is_rollback: bool = Field(
        default=False,
        description="If True, this release commands edge clients to revert to a previous trusted state",
    )
    rollback_target_version: Annotated[str | None, Field(default=None, max_length=32)] = None
    release_notes: Annotated[str, Field(default="", max_length=4096)] = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReleaseEligibilityReport(BaseModel):
    """Result of verifying whether an evaluated candidate defense meets criteria for release consideration."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: UUID
    evaluation_report_id: UUID
    is_eligible: bool
    evaluation_verdict: str
    reasons: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReleaseAuthorization(BaseModel):
    """Explicit administrative or deployment workflow authorization to release a candidate to a channel."""

    model_config = ConfigDict(extra="forbid")

    authorization_id: UUID = Field(default_factory=uuid4)
    release_id: UUID
    candidate_id: UUID
    evaluation_report_id: UUID
    policy_version: str
    target_channel: ReleaseChannel
    authorized_by: Annotated[str, Field(min_length=2, max_length=128)]
    rationale: Annotated[str, Field(min_length=5, max_length=2048)]
    authorized_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RolloutState(BaseModel):
    """Real-time rollout progression status and metrics for a release."""

    model_config = ConfigDict(extra="forbid")

    release_id: UUID
    channel: ReleaseChannel
    stage: RolloutStage
    rollout_percentage: Annotated[float, Field(ge=0.0, le=100.0)]
    is_paused: bool = False
    total_targeted_clients: int = 0
    successful_installs: int = 0
    failed_installs: int = 0
    rollback_count: int = 0
    failure_rate: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SigningKeyMetadata(BaseModel):
    """Public metadata describing a signing key authority."""

    model_config = ConfigDict(extra="forbid")

    key_id: Annotated[str, Field(min_length=4, max_length=64)]
    algorithm: Annotated[str, Field(default="ed25519", max_length=32)]
    public_key_pem: str
    status: KeyStatus
    valid_from: datetime
    valid_until: datetime | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


class TrustAnchorSet(BaseModel):
    """Collection of trusted active and revoked public keys distributed to edge clients."""

    model_config = ConfigDict(extra="forbid")

    active_keys: list[SigningKeyMetadata] = Field(default_factory=list)
    revoked_keys: list[SigningKeyMetadata] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
