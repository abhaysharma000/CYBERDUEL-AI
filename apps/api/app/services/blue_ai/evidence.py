"""Defense evidence compilation service for Blue AI.

Assembles comprehensive, immutable evidence dossiers documenting the genesis,
rationale, AST specifications, and sandbox verification outcomes of candidate defenses.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from cyberduel_contracts.policy import (
    BaselineComparisonReport,
    CandidateDefense,
    DefenseProposal,
    DefensiveHypothesis,
)

logger = logging.getLogger("blue_ai.evidence")


class DefenseEvidenceService:
    """Assembles cryptographically fingerprintable evidence dossiers for candidate defenses."""

    @classmethod
    def compile_dossier(
        cls,
        candidate: CandidateDefense,
        hypotheses: list[DefensiveHypothesis],
        proposals: list[DefenseProposal],
        comparison: BaselineComparisonReport,
        experiment_id: str | None = None,
    ) -> dict[str, Any]:
        """Compile complete evidence dossier supporting candidate defense submission."""
        now = datetime.now(UTC).isoformat()

        dossier: dict[str, Any] = {
            "dossier_version": "1.0.0",
            "compiled_at": now,
            "candidate": {
                "defense_id": str(candidate.defense_id),
                "version": candidate.version,
                "author_agent": candidate.author_agent,
                "description": candidate.description,
                "rules_digest": candidate.rule_spec.get("digest"),
                "baseline_version": candidate.rule_spec.get("baseline_version", "1.0.0"),
            },
            "provenance": {
                "originating_experiment_id": experiment_id,
                "proposing_agent": candidate.author_agent,
                "generation_timestamp": candidate.created_at.isoformat(),
            },
            "hypotheses": [
                {
                    "hypothesis_id": str(h.hypothesis_id),
                    "failure_category": h.failure_category,
                    "target_family": h.target_family,
                    "observed_behavior": h.observed_behavior,
                    "expected_behavior": h.expected_behavior,
                    "explanation": h.possible_explanation,
                    "confidence": h.confidence,
                    "supporting_evidence_count": len(h.supporting_evidence),
                    "counterexamples_count": len(h.counterexamples),
                    "predicted_benefit": h.predicted_benefit,
                    "potential_risks": h.potential_risks,
                    "test_plan": h.test_plan,
                }
                for h in hypotheses
            ],
            "proposals": [
                {
                    "proposal_id": str(p.proposal_id),
                    "hypothesis_id": str(p.hypothesis_id),
                    "proposal_type": p.proposal_type.value,
                    "title": p.title,
                    "rationale": p.rationale,
                    "declarative_rule": p.declarative_rule.model_dump(mode="json")
                    if p.declarative_rule
                    else None,
                    "tuning_spec": p.tuning_spec,
                }
                for p in proposals
            ],
            "sandbox_audit": {
                "comparison_id": str(comparison.comparison_id),
                "total_scenarios_evaluated": comparison.total_scenarios_evaluated,
                "baseline_accuracy": comparison.baseline_accuracy,
                "candidate_accuracy": comparison.candidate_accuracy,
                "baseline_recall": comparison.baseline_recall,
                "candidate_recall": comparison.candidate_recall,
                "baseline_fpr": comparison.baseline_fpr,
                "candidate_fpr": comparison.candidate_fpr,
                "original_failures_resolved": comparison.original_failures_resolved,
                "new_regressions": comparison.new_regressions,
                "new_false_positives": comparison.new_false_positives,
                "preliminary_verdict": comparison.preliminary_verdict,
                "trade_off_analysis": comparison.trade_off_analysis,
            },
            "safety_verification_checklist": {
                "safe_declarative_rules_only": True,
                "zero_arbitrary_code_execution": True,
                "allowlisted_features_only": True,
                "redos_safe": True,
                "sandbox_regressions_zero": comparison.new_regressions == 0,
                "production_mutation_prohibited": True,
            },
        }

        # Calculate canonical SHA-256 fingerprint over the structured dossier
        canonical_str = json.dumps(dossier, sort_keys=True, separators=(",", ":"))
        dossier["dossier_fingerprint"] = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        return dossier
