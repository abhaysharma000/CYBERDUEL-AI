"""Configuration and resource guardrails for autonomous self-improvement cycles."""

from cyberduel_contracts.evaluation import AcceptancePolicyConfig
from pydantic import BaseModel, ConfigDict, Field


class ControllerPolicyConfig(BaseModel):
    """Resource bounds, safety timeouts, and thresholds governing self-improvement loops."""

    model_config = ConfigDict(extra="forbid")

    max_candidates_per_cycle: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum candidate defenses allowed to be generated and audited in one cycle",
    )
    max_evaluations: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum total evaluation requests across the cycle lifetime",
    )
    max_scenarios_per_eval: int = Field(
        default=100,
        ge=10,
        le=1000,
        description="Maximum scenario count audited per evaluation request",
    )
    cycle_timeout_seconds: float = Field(
        default=120.0,
        ge=10.0,
        le=600.0,
        description="Hard wall-clock timeout for the entire improvement cycle",
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Retry attempts permitted when a candidate proposal fails preliminary checks",
    )
    benchmark_manifest_version: str = Field(
        default="benchmark-golden-v1",
        description="Standardized benchmark manifest used by the Independent Evaluation Engine",
    )
    acceptance_policy: AcceptancePolicyConfig = Field(
        default_factory=AcceptancePolicyConfig,
        description="Configurable acceptance gates for candidate promotion",
    )
    target_failure_categories: list[str] = Field(
        default_factory=list,
        description="Optional restriction to specific failure categories (e.g. evasion, over_detection)",
    )
