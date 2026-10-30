"""Explicit, configurable risk scoring and explainable decision engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cyberduel_contracts.analysis import EvidenceItem
from cyberduel_contracts.enums import Decision, ProvenanceType, ThreatSeverity


@dataclass(frozen=True)
class ScoringPolicyConfig:
    """Configurable thresholds and weights for threat evaluation."""

    policy_version: str = "2026.10.1"
    warn_threshold: float = 0.35
    block_threshold: float = 0.70
    verified_indicator_score: float = 0.95
    whitelist_score: float = 0.02
    fail_safe_decision: Decision = Decision.WARN
    fail_safe_score: float = 0.50


@dataclass(frozen=True)
class ScoringOutcome:
    """Complete explainable verdict produced by the RiskScoringEngine."""

    threat_score: float
    decision: Decision
    evidence: list[EvidenceItem]
    explanation: str
    provenance: ProvenanceType
    confidence: float | None
    matched_indicators: list[str]
    fail_safe_applied: bool


class RiskScoringEngine:
    """Combines threat intelligence, heuristic indicators, and ML scores into explainable verdicts."""

    def __init__(self, config: ScoringPolicyConfig | None = None) -> None:
        self.config = config or ScoringPolicyConfig()

    def evaluate(
        self,
        indicator_matches: list[dict[str, Any]],
        heuristic_evidence: list[EvidenceItem],
        ml_score: float | None = None,
        is_whitelisted: bool = False,
    ) -> ScoringOutcome:
        """Combine all detection layers into an explainable, bounded score and decision."""
        # 1. Whitelist Override
        if is_whitelisted:
            whitelist_evidence = [e for e in heuristic_evidence if e.category == "whitelist"] or [
                EvidenceItem(
                    category="whitelist",
                    reason="Destination domain is present on the verified baseline whitelist.",
                    severity=ThreatSeverity.NONE,
                    confidence=0.99,
                )
            ]
            return ScoringOutcome(
                threat_score=self.config.whitelist_score,
                decision=Decision.ALLOW,
                evidence=whitelist_evidence,
                explanation="Destination matches verified benign infrastructure; access permitted.",
                provenance=ProvenanceType.LOCAL_RULE,
                confidence=0.99,
                matched_indicators=[],
                fail_safe_applied=False,
            )

        # 2. Verified Malicious Threat Intelligence Match
        verified_threats = [
            ind
            for ind in indicator_matches
            if ind.get("verification_status") == "verified"
            and ind.get("classification") in {"phishing", "malware", "scam", "c2"}
        ]
        if verified_threats:
            top_match = verified_threats[0]
            intel_evidence = [
                EvidenceItem(
                    category="threat_intelligence",
                    reason=(
                        f"Target matched verified malicious {top_match.get('indicator_type', 'indicator')} "
                        f"classified as '{top_match.get('classification', 'malicious')}' "
                        f"(Source: {top_match.get('source', 'curated_intel')})."
                    ),
                    severity=ThreatSeverity.CRITICAL,
                    confidence=float(top_match.get("confidence") or 0.98),
                )
            ]
            combined_evidence = intel_evidence + [
                e for e in heuristic_evidence if e.category != "threat_intelligence"
            ]
            return ScoringOutcome(
                threat_score=self.config.verified_indicator_score,
                decision=Decision.BLOCK,
                evidence=combined_evidence,
                explanation=(
                    f"Blocked due to verified threat intelligence match: "
                    f"{top_match.get('classification', 'threat').upper()} indicator."
                ),
                provenance=ProvenanceType.CLOUD_ANALYSIS,
                confidence=0.98,
                matched_indicators=[
                    str(ind.get("normalized_value", "")) for ind in verified_threats
                ],
                fail_safe_applied=False,
            )

        # 3. Combine Heuristics using Soft Independence Saturation
        # Formula: S = 1.0 - Product(1.0 - weight_i) to prevent runaway arithmetic sums
        # Severity weights: CRITICAL=0.85, HIGH=0.60, MEDIUM=0.35, LOW=0.20, NONE=0.0
        severity_weight_map = {
            ThreatSeverity.CRITICAL: 0.85,
            ThreatSeverity.HIGH: 0.60,
            ThreatSeverity.MEDIUM: 0.35,
            ThreatSeverity.LOW: 0.20,
            ThreatSeverity.NONE: 0.0,
        }

        # Deduplicate evidence categories so multiple triggers under the same category don't double count
        seen_categories: set[str] = set()
        unique_weights: list[float] = []
        filtered_evidence: list[EvidenceItem] = []

        for item in heuristic_evidence:
            if item.category in seen_categories:
                # Include in explanation but avoid double weight counting
                filtered_evidence.append(item)
                continue
            seen_categories.add(item.category)
            w = severity_weight_map.get(item.severity, 0.20)
            unique_weights.append(w)
            filtered_evidence.append(item)

        # Compute combined score
        if unique_weights:
            product = 1.0
            for w in unique_weights:
                product *= 1.0 - min(0.95, max(0.0, w))
            heuristic_score = 1.0 - product
        else:
            heuristic_score = 0.05

        # Incorporate optional ML score with gentle ensemble blending (70% heuristics, 30% ML)
        if ml_score is not None:
            blended_score = 0.70 * heuristic_score + 0.30 * ml_score
            provenance = ProvenanceType.MODEL_INFERENCE
        else:
            blended_score = heuristic_score
            provenance = ProvenanceType.LOCAL_RULE

        final_score = round(max(0.0, min(1.0, blended_score)), 4)

        # 4. Map Decision via Configured Thresholds
        if final_score >= self.config.block_threshold:
            decision = Decision.BLOCK
            explanation = (
                f"Blocked: high cumulative risk score ({final_score:.2f}) from "
                f"{len(filtered_evidence)} suspicious characteristics."
            )
        elif final_score >= self.config.warn_threshold:
            decision = Decision.WARN
            explanation = (
                f"Warning: suspicious characteristics detected ({final_score:.2f}); "
                f"proceed with caution."
            )
        else:
            decision = Decision.ALLOW
            explanation = "No significant risk indicators identified; destination allowed."

        confidence = 0.85 if len(filtered_evidence) > 0 else 0.95

        return ScoringOutcome(
            threat_score=final_score,
            decision=decision,
            evidence=filtered_evidence,
            explanation=explanation,
            provenance=provenance,
            confidence=confidence,
            matched_indicators=[],
            fail_safe_applied=False,
        )

    def apply_fail_safe(self, reason: str) -> ScoringOutcome:
        """Explicit fail-safe response when critical analysis subsystems are unavailable."""
        return ScoringOutcome(
            threat_score=self.config.fail_safe_score,
            decision=self.config.fail_safe_decision,
            evidence=[
                EvidenceItem(
                    category="fail_safe",
                    reason=f"Analysis engine operating in fail-safe mode: {reason}",
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.50,
                )
            ],
            explanation=f"Fail-safe protection applied: {reason}",
            provenance=ProvenanceType.LOCAL_RULE,
            confidence=None,
            matched_indicators=[],
            fail_safe_applied=True,
        )
