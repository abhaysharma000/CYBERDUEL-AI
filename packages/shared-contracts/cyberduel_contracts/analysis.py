"""Schemas for resource analysis requests, threat evaluations, and evidence."""

from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from cyberduel_contracts.enums import Decision, ProvenanceType, ThreatSeverity


class EvidenceItem(BaseModel):
    """Specific verifiable evidence or reason contributing to a threat decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: Annotated[
        str,
        Field(
            min_length=2,
            max_length=64,
            description="Category of indicator, e.g. 'reputation', 'homograph', 'phishing_keywords'",
        ),
    ]
    reason: Annotated[
        str,
        Field(
            min_length=3,
            max_length=512,
            description="Human-readable explanation of the detected indicator",
        ),
    ]
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence: Annotated[
        float | None,
        Field(
            ge=0.0,
            le=1.0,
            description="Confidence score for this specific evidence item, if supported",
        ),
    ] = None


class ResourceAnalysisRequest(BaseModel):
    """Request payload for evaluating a URL, domain, or digital resource."""

    model_config = ConfigDict(extra="forbid")

    resource_url: Annotated[
        str | None,
        Field(
            default=None,
            max_length=2048,
            description="Full resource URL if permitted by client privacy settings",
        ),
    ]
    normalized_identifier: Annotated[
        str,
        Field(
            min_length=8,
            max_length=256,
            description="Privacy-preserving normalized hash (e.g., SHA256 of canonical URL or domain)",
        ),
    ]
    resource_type: Literal["url", "domain", "ip", "file_hash", "text_snippet"] = "url"
    client_id: Annotated[
        str | None,
        Field(
            default=None,
            max_length=128,
            description="Anonymous or registered client ID for telemetry collation",
        ),
    ]
    client_version: Annotated[
        str | None,
        Field(
            max_length=32,
            description="Version of calling client (extension/mobile)",
        ),
    ] = None
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Non-identifying context metadata such as request origin or protocol",
    )


class ThreatAnalysisResult(BaseModel):
    """Standardized decision payload for an analyzed resource."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this analysis run",
    )
    normalized_identifier: Annotated[
        str,
        Field(
            min_length=8,
            max_length=256,
            description="Normalized hash or identifier of analyzed resource",
        ),
    ]
    threat_score: Annotated[
        float,
        Field(
            ge=0.0,
            le=1.0,
            description="Calibrated threat score: 0.0 (benign) to 1.0 (confirmed malicious)",
        ),
    ]
    decision: Decision = Field(
        ...,
        description="Definitive action decision: allow, warn, or block",
    )
    evidence: list[EvidenceItem] = Field(
        default_factory=list,
        description="Verifiable evidence and rationale supporting the decision",
    )
    engine_version: Annotated[
        str,
        Field(
            min_length=1,
            max_length=32,
            description="Version of the detection engine generating this verdict",
        ),
    ]
    policy_version: Annotated[
        str,
        Field(
            min_length=1,
            max_length=32,
            description="Active defensive policy version used for rule evaluation",
        ),
    ]
    confidence: Annotated[
        float | None,
        Field(
            ge=0.0,
            le=1.0,
            description="Statistical confidence measure; None if engine does not estimate confidence",
        ),
    ] = None
    provenance: ProvenanceType = Field(
        ...,
        description="Source of determination: local_rule, model_inference, or cloud_analysis",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when analysis was conducted",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="Cache expiration timestamp for this verdict",
    )


class URLAnalysisRequest(BaseModel):
    """Primary request payload for full URL threat evaluation."""

    model_config = ConfigDict(extra="forbid")

    url: Annotated[
        str,
        Field(
            min_length=3,
            max_length=4096,
            description="Full URL to evaluate (http or https)",
        ),
    ]
    client_id: Annotated[
        str | None,
        Field(
            default=None,
            max_length=128,
            description="Anonymous client installation ID",
        ),
    ] = None
    client_version: Annotated[
        str | None,
        Field(
            default=None,
            max_length=32,
            description="Calling edge client version",
        ),
    ] = None
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-identifying telemetry metadata",
    )


class URLAnalysisResponse(BaseModel):
    """Detailed machine-readable and explainable threat analysis response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this analysis run",
    )
    input_validation_status: Annotated[
        str,
        Field(description="Status of input parsing: 'valid' or 'malformed'"),
    ]
    safe_normalized_url: Annotated[
        str,
        Field(
            description="Canonical normalized URL with credentials and sensitive query tokens redacted"
        ),
    ]
    normalized_identifier: Annotated[
        str,
        Field(description="SHA-256 digest of canonical URL"),
    ]
    decision: Decision = Field(
        ...,
        description="Actionable verdict: allow, warn, or block",
    )
    threat_score: Annotated[
        float,
        Field(
            ge=0.0,
            le=1.0,
            description="Calibrated threat score from 0.0 (benign) to 1.0 (confirmed malicious)",
        ),
    ]
    evidence: list[EvidenceItem] = Field(
        default_factory=list,
        description="Verifiable evidence and rationale supporting the verdict",
    )
    matched_indicators: list[str] = Field(
        default_factory=list,
        description="Matched verified threat intelligence indicator values",
    )
    engine_version: str
    policy_version: str
    confidence: float | None = None
    provenance: ProvenanceType
    explanation: Annotated[
        str,
        Field(description="Human-readable plain text explanation of the decision"),
    ]
    fail_safe_applied: bool = False
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
