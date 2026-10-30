"""Prioritization engine for defensive investigations and gap analysis.

Ranks failure findings based on severity, discrepancy impact, prevalence,
and historical feedback from previous candidate evaluations.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from cyberduel_contracts.enums import ThreatSeverity
from cyberduel_contracts.lab import FailureFinding, ScenarioContract


@dataclass
class FailureCluster:
    """Clustered group of detection failures sharing category and behavioral pattern."""

    cluster_id: str
    failure_category: str
    target_family: str
    discrepancy_type: str
    severity: ThreatSeverity | str
    findings: list[FailureFinding] = field(default_factory=list)
    scenarios: list[ScenarioContract] = field(default_factory=list)
    affected_count: int = 0
    sample_urls: list[str] = field(default_factory=list)


@dataclass
class PrioritizedFailureGroup:
    """A scored and ranked failure cluster ready for defensive hypothesis generation."""

    cluster: FailureCluster
    priority_score: float
    urgency_rank: int
    rationale: str
    recommended_focus: str


class DefensePrioritizationEngine:
    """Calculates defensive investigation priorities from Red AI failure clusters."""

    SEVERITY_WEIGHTS = {
        ThreatSeverity.CRITICAL: 1.00,
        ThreatSeverity.HIGH: 0.80,
        ThreatSeverity.MEDIUM: 0.50,
        ThreatSeverity.LOW: 0.25,
        "critical": 1.00,
        "high": 0.80,
        "medium": 0.50,
        "low": 0.25,
    }

    DISCREPANCY_WEIGHTS = {
        "false_negative": 1.30,  # Missed attack: urgent defense gap
        "evasion": 1.20,  # Adversarial bypass
        "underclassification": 1.10,
        "false_positive": 0.90,  # Overblocking benign traffic: important, but not exploit vector
        "overclassification": 0.85,
    }

    @classmethod
    def score_cluster(
        cls,
        cluster: FailureCluster,
        negative_feedback_categories: set[str] | None = None,
    ) -> tuple[float, str]:
        """Compute deterministic priority score (0.0 to 1.0+) and explanation."""
        # 1. Base severity weight
        sev_weight = cls.SEVERITY_WEIGHTS.get(cluster.severity, 0.50)

        # 2. Discrepancy impact multiplier
        disc_weight = cls.DISCREPANCY_WEIGHTS.get(cluster.discrepancy_type.lower(), 1.00)

        # 3. Prevalence / frequency factor: logarithmic growth bounded at +0.35
        # More frequent failures get higher attention
        count = max(1, cluster.affected_count or len(cluster.scenarios))
        prevalence_bonus = min(0.35, math.log10(count + 1) * 0.25)

        base_score = (sev_weight * disc_weight) + prevalence_bonus

        # 4. Learning dampener: if previous candidate proposals for this category were repeatedly rejected
        # damp slightly to explore alternative clusters first
        penalty = 0.0
        if (
            negative_feedback_categories
            and cluster.failure_category in negative_feedback_categories
        ):
            penalty = 0.15

        final_score = max(0.05, round(base_score - penalty, 4))

        sev_str = (
            cluster.severity.value if hasattr(cluster.severity, "value") else str(cluster.severity)
        )
        rationale = (
            f"Severity={sev_str} ({sev_weight:.2f}) x "
            f"Impact={cluster.discrepancy_type} ({disc_weight:.2f}) + "
            f"Prevalence={count} (+{prevalence_bonus:.2f})"
        )
        if penalty > 0:
            rationale += f" - HistoricalRejectionPenalty(-{penalty:.2f})"

        return final_score, rationale

    @classmethod
    def rank_clusters(
        cls,
        clusters: list[FailureCluster],
        negative_feedback_categories: set[str] | None = None,
    ) -> list[PrioritizedFailureGroup]:
        """Rank all failure clusters in descending order of defensive priority."""
        scored: list[tuple[float, str, FailureCluster]] = []

        for cluster in clusters:
            score, rationale = cls.score_cluster(cluster, negative_feedback_categories)
            scored.append((score, rationale, cluster))

        # Sort descending by priority score
        scored.sort(key=lambda x: x[0], reverse=True)

        ranked: list[PrioritizedFailureGroup] = []
        for rank, (score, rationale, cluster) in enumerate(scored, start=1):
            focus = (
                f"Address {cluster.failure_category} ({cluster.discrepancy_type}) "
                f"affecting {cluster.affected_count} scenarios in {cluster.target_family}"
            )
            ranked.append(
                PrioritizedFailureGroup(
                    cluster=cluster,
                    priority_score=score,
                    urgency_rank=rank,
                    rationale=rationale,
                    recommended_focus=focus,
                )
            )

        return ranked
