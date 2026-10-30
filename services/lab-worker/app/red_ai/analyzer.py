"""Failure Analyzer and Laboratory Evaluation Metrics Calculator.

Groups discrepancies into analytical hypotheses and computes transparent evaluation metrics.
Distinguishes confirmed discrepancy observations from explanatory hypotheses.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from uuid import UUID, uuid4

from cyberduel_contracts.enums import Decision, DiscrepancyType, ExpectedClass, FailureCategory
from cyberduel_contracts.lab import FailureFinding, ScenarioExecutionResult


class FailureAnalyzer:
    """Analyzes execution discrepancies and extracts structured investigation hypotheses."""

    @classmethod
    def analyze_executions(
        cls,
        experiment_id: UUID,
        executions: list[ScenarioExecutionResult],
    ) -> list[FailureFinding]:
        """Group observed discrepancies into failure findings and structured hypotheses."""
        discrepancies = [e for e in executions if e.is_discrepancy]
        if not discrepancies:
            return []

        # Cluster by discrepancy type and scenario family
        clusters: dict[tuple[str, str], list[ScenarioExecutionResult]] = defaultdict(list)
        for d in discrepancies:
            clusters[(d.discrepancy_type, d.scenario_family)].append(d)

        findings: list[FailureFinding] = []

        for (dtype, family), exec_list in clusters.items():
            rep_ids = [e.scenario_id for e in exec_list[:5]]
            count = len(exec_list)

            if dtype == DiscrepancyType.FALSE_POSITIVE.value:
                cat = FailureCategory.OVER_DETECTION.value
                hypo = (
                    f"Hypothesis: Over-detection in family '{family}'. Legitimate controls containing "
                    f"benign tokens or structural attributes were penalized beyond acceptable threshold."
                )
                remedy = (
                    f"Calibrate heuristic rules associated with '{family}' to require compounding evidence "
                    f"or establish domain context whitelisting before elevating risk score."
                )
                sev = "high"

            elif dtype == DiscrepancyType.FALSE_NEGATIVE.value:
                cat = FailureCategory.EVASION.value
                hypo = (
                    f"Hypothesis: Evasion vulnerability in family '{family}'. Synthetic adversarial patterns "
                    f"bypassed heuristic triggers and reputation lookups, resulting in an 'allow' verdict."
                )
                remedy = f"Formulate candidate defensive signatures targeting obfuscated variations in '{family}'."
                sev = "critical"

            elif dtype == DiscrepancyType.UNDERCONFIDENT.value:
                cat = FailureCategory.POLICY_MISCALIBRATION.value
                hypo = (
                    f"Hypothesis: Underconfident risk scoring in family '{family}'. Malicious target received "
                    f"only a 'warn' decision rather than an authoritative 'block'."
                )
                remedy = f"Adjust soft saturation weight or increase evidence severity weighting for '{family}'."
                sev = "medium"

            elif dtype == DiscrepancyType.OVERLY_AGGRESSIVE.value:
                cat = FailureCategory.POLICY_MISCALIBRATION.value
                hypo = (
                    f"Hypothesis: Overly aggressive thresholding in family '{family}'. Moderate risk scenario "
                    f"was promoted to 'block' without definitive critical indicator."
                )
                remedy = "Review block threshold ceiling (currently 0.70) or downgrade single-feature weights."
                sev = "medium"

            elif dtype == DiscrepancyType.PARSING_ERROR.value:
                cat = FailureCategory.PARSING_INCONSISTENCY.value
                hypo = (
                    f"Hypothesis: Parser anomaly in family '{family}'. Syntactically valid URL caused "
                    f"unexpected validation failure or normalization exception."
                )
                remedy = "Harden URLNormalizer and URLValidator to gracefully canonicalize this representation."
                sev = "high"

            else:
                cat = FailureCategory.UNKNOWN.value
                hypo = f"Hypothesis: Unclassified discrepancy observed in family '{family}'."
                remedy = "Manual forensic audit required."
                sev = "low"

            findings.append(
                FailureFinding(
                    finding_id=uuid4(),
                    experiment_id=experiment_id,
                    failure_category=cat,
                    discrepancy_type=dtype,
                    hypothesis=hypo,
                    affected_scenarios_count=count,
                    representative_scenario_ids=rep_ids,
                    suggested_remedy=remedy,
                    severity=sev,  # type: ignore[arg-type]
                )
            )

        return findings

    @classmethod
    def compute_metrics(
        cls,
        executions: list[ScenarioExecutionResult],
    ) -> dict[str, Any]:
        """Compute comprehensive evaluation metrics across executed scenarios."""
        total = len(executions)
        if total == 0:
            return {
                "total_scenarios": 0,
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "false_positive_rate": 0.0,
                "discrepancy_rate": 0.0,
                "average_latency_ms": 0.0,
                "decision_distribution": {},
                "family_breakdown": {},
            }

        # Filter out uncertain ground-truth cases from binary metrics
        evaluable = [
            e
            for e in executions
            if e.expected_class in {ExpectedClass.BENIGN.value, ExpectedClass.MALICIOUS.value}
        ]

        tp = sum(
            1
            for e in evaluable
            if e.expected_class == ExpectedClass.MALICIOUS.value
            and e.actual_decision in {Decision.BLOCK, Decision.WARN}
        )
        fp = sum(
            1
            for e in evaluable
            if e.expected_class == ExpectedClass.BENIGN.value
            and e.actual_decision in {Decision.BLOCK, Decision.WARN}
        )
        tn = sum(
            1
            for e in evaluable
            if e.expected_class == ExpectedClass.BENIGN.value
            and e.actual_decision == Decision.ALLOW
        )
        fn = sum(
            1
            for e in evaluable
            if e.expected_class == ExpectedClass.MALICIOUS.value
            and e.actual_decision == Decision.ALLOW
        )

        n_eval = len(evaluable)
        accuracy = (tp + tn) / n_eval if n_eval > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        total_discrepancies = sum(1 for e in executions if e.is_discrepancy)
        discrepancy_rate = total_discrepancies / total
        avg_latency = sum(e.duration_ms for e in executions) / total

        # Decision distributions
        dec_dist: dict[str, int] = defaultdict(int)
        for e in executions:
            dec_dist[e.actual_decision.value] += 1

        # Family breakdown
        family_map: dict[str, list[ScenarioExecutionResult]] = defaultdict(list)
        for e in executions:
            family_map[e.scenario_family].append(e)

        family_breakdown: dict[str, dict[str, Any]] = {}
        for fam, fam_execs in family_map.items():
            fam_total = len(fam_execs)
            fam_disc = sum(1 for e in fam_execs if e.is_discrepancy)
            family_breakdown[fam] = {
                "total": fam_total,
                "discrepancies": fam_disc,
                "accuracy": (fam_total - fam_disc) / fam_total if fam_total > 0 else 0.0,
            }

        return {
            "total_scenarios": total,
            "evaluable_scenarios": n_eval,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "discrepancy_rate": round(discrepancy_rate, 4),
            "average_latency_ms": round(avg_latency, 2),
            "decision_distribution": dict(dec_dist),
            "family_breakdown": family_breakdown,
        }
