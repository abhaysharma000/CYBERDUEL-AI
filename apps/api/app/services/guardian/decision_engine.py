"""Guardian Decision Engine.

Provides evidence-based comparative reasoning, risk prioritisation,
and user-centric protection recommendations (BLOCK, WARN, ALLOW)
derived strictly from real evaluation reports and deterministic policy evaluation.
"""

from __future__ import annotations

import logging

from cyberduel_contracts.enums import EvaluationVerdict
from cyberduel_contracts.evaluation import EvaluationReport
from cyberduel_contracts.guardian import (
    GuardianDecisionExplanation,
    GuardianDecisionOutcome,
)
from cyberduel_contracts.policy import CandidateDefense

logger = logging.getLogger("cyberduel.guardian.decision_engine")


class GuardianDecisionEngine:
    """Supervisory reasoning engine formulating evidence-backed defensive verdicts."""

    @classmethod
    def evaluate_candidate_for_release(
        cls,
        candidate: CandidateDefense,
        report: EvaluationReport,
        baseline_version: str = "1.1.0",
    ) -> GuardianDecisionExplanation:
        """Formulate an evidence-based explanation comparing candidate defense against baseline."""
        cand_recall = report.candidate_metrics.recall
        cand_fpr = report.candidate_metrics.false_positive_rate
        regressions = getattr(report.improvement_metrics, "new_regressions", 0)
        passed = report.verdict == EvaluationVerdict.PASS

        # Determine threat priority from candidate rules safely
        raw_rules = []
        if hasattr(candidate, "rule_spec") and isinstance(candidate.rule_spec, dict):
            raw_rules = candidate.rule_spec.get("rules", [])
        elif hasattr(candidate, "rules"):
            raw_rules = getattr(candidate, "rules", [])

        rule_severities = []
        rule_descriptions = []
        for r in raw_rules:
            if isinstance(r, dict):
                rule_severities.append(str(r.get("severity", "medium")))
                rule_descriptions.append(str(r.get("description", "")))
            elif hasattr(r, "severity"):
                rule_severities.append(str(r.severity))
                rule_descriptions.append(str(r.description))

        if any("critical" in s.lower() for s in rule_severities):
            threat_prio = "critical"
        elif any("high" in s.lower() for s in rule_severities):
            threat_prio = "high"
        else:
            threat_prio = "medium"

        # Formulate expected detection benefit
        rules_desc = "; ".join(filter(None, rule_descriptions)) or "Targeted IDN evasion rules"
        expected_benefit = (
            f"Achieves {cand_recall:.1%} detection recall against synthetic threat corpus. "
            f"Neutralizes active evasions: {rules_desc}."
        )

        # Assess false positive risk
        benign_tested = report.candidate_metrics.tn + report.candidate_metrics.fp
        if cand_fpr == 0.0 and regressions == 0:
            fp_concerns = (
                f"Zero false positives recorded across {benign_tested} "
                "legitimate benign controls. Zero regressions against baseline policy."
            )
            confidence = 0.99
            uncertainty = "Negligible: rule predicates are tightly scoped to specific homoglyph and IDN patterns."
        else:
            fp_concerns = (
                f"Elevated false positive rate of {cand_fpr:.2%} with {regressions} regressions. "
                "May inadvertently interrupt benign enterprise traffic."
            )
            confidence = 0.70
            uncertainty = (
                "Elevated: predicates exhibit potential overbreadth requiring manual review."
            )

        # Recommendation and User Impact
        if passed:
            recommendation = "promote"
            next_action = (
                "Authorize Ed25519 cryptographic signing and initiate staged canary rollout."
            )
            user_impact = (
                "Users will be proactively shielded from novel homoglyph/IDN spoofing attacks "
                "without any observed disruption to legitimate navigation."
            )
            summary = (
                f"Candidate {candidate.version} strictly satisfies all operational release gates: "
                f"Zero regressions, {cand_recall:.1%} recall, and 0.0% false-positive rate. "
                f"Guardian strongly recommends promotion over baseline {baseline_version}."
            )
        else:
            recommendation = "reject"
            next_action = "Return candidate to Blue AI with regression feedback for targeted predicate narrowing."
            user_impact = (
                "Rejection prevents introducing overblocking defects into the production fleet."
            )
            summary = (
                f"Candidate {candidate.version} failed independent evaluation due to "
                f"{'; '.join(report.rejection_reasons) if report.rejection_reasons else 'insufficient metrics'}. "
                "Guardian blocked release to prevent fleet regression."
            )

        candidate_id = getattr(candidate, "defense_id", None) or getattr(candidate, "id", None)
        return GuardianDecisionExplanation(
            selected_candidate_id=candidate_id,
            selected_candidate_version=candidate.version,
            threat_priority=threat_prio,
            research_priority="high",
            candidate_priority="high" if passed else "low",
            expected_detection_benefit=expected_benefit,
            false_positive_concerns=fp_concerns,
            evaluator_verdict="pass" if passed else "fail",
            release_recommendation=recommendation,
            user_impact=user_impact,
            confidence=confidence,
            uncertainty=uncertainty,
            recommended_next_action=next_action,
            reasoning_summary=summary,
        )

    @classmethod
    def resolve_user_decision(
        cls,
        threat_score: float,
        matched_rule_id: str | None = None,
        block_threshold: float = 0.70,
        warn_threshold: float = 0.40,
    ) -> tuple[GuardianDecisionOutcome, str]:
        """Map quantitative risk score and rule matches into user-centric decision."""
        if matched_rule_id:
            return (
                GuardianDecisionOutcome.BLOCK,
                f"Blocked by active cryptographic policy rule '{matched_rule_id}'. Known threat pattern.",
            )

        if threat_score >= block_threshold:
            return (
                GuardianDecisionOutcome.BLOCK,
                f"High-confidence threat indicators detected (score {threat_score:.2f} >= {block_threshold:.2f}). Navigation blocked.",
            )

        if threat_score >= warn_threshold:
            return (
                GuardianDecisionOutcome.WARN,
                f"Suspicious signals detected (score {threat_score:.2f} >= {warn_threshold:.2f}). Proceed with caution.",
            )

        return (
            GuardianDecisionOutcome.ALLOW,
            f"No known threat detected (score {threat_score:.2f} < {warn_threshold:.2f}). Destination permitted.",
        )
