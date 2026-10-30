"""Configurable acceptance policy engine enforcing strict security gates."""

import logging

from cyberduel_contracts.enums import DatasetSplitType, EvaluationStatus, EvaluationVerdict
from cyberduel_contracts.evaluation import (
    AcceptancePolicyConfig,
    ConfusionMatrix,
    ImprovementMetrics,
    OperationalMetrics,
)
from cyberduel_contracts.policy import CandidateDefense

logger = logging.getLogger("evaluator.acceptance")


class AcceptancePolicyEngine:
    """Evaluates candidate performance against formal security and reliability thresholds."""

    @classmethod
    def evaluate(
        cls,
        candidate: CandidateDefense,
        candidate_metrics: ConfusionMatrix,
        baseline_metrics: ConfusionMatrix,
        split_metrics: dict[str, ConfusionMatrix],
        improvement_metrics: ImprovementMetrics,
        operational_metrics: OperationalMetrics,
        policy: AcceptancePolicyConfig,
    ) -> tuple[EvaluationVerdict, EvaluationStatus, str, list[str], list[str]]:
        """Evaluate candidate defense against acceptance policy.

        Returns:
            (verdict, status, rationale, acceptance_reasons, rejection_reasons)
        """
        acceptance_reasons: list[str] = []
        rejection_reasons: list[str] = []

        # Gate 1: Integrity Check
        if policy.require_digest_verification and not candidate.rule_spec:
            rejection_reasons.append("Candidate rule specification is empty or missing")
        else:
            acceptance_reasons.append("Candidate passed structural specification integrity check")

        # Gate 2: Zero Regressions Gate
        if improvement_metrics.new_regressions > policy.max_allowed_regressions:
            rejection_reasons.append(
                f"Candidate introduced {improvement_metrics.new_regressions} regressions "
                f"(max allowed: {policy.max_allowed_regressions})"
            )
        else:
            acceptance_reasons.append(
                f"Zero regressions detected on verified benchmarks ({improvement_metrics.new_regressions} <= {policy.max_allowed_regressions})"
            )

        # Gate 3: False Positive Rate Ceiling
        if candidate_metrics.false_positive_rate > policy.max_allowed_fpr:
            rejection_reasons.append(
                f"Candidate FPR {candidate_metrics.false_positive_rate:.2%} exceeded ceiling "
                f"of {policy.max_allowed_fpr:.2%}"
            )
        else:
            acceptance_reasons.append(
                f"Candidate FPR {candidate_metrics.false_positive_rate:.2%} is within acceptable limit (<= {policy.max_allowed_fpr:.2%})"
            )

        # Gate 4: Target Failure Resolution Gate
        if improvement_metrics.original_failures_total > 0:
            if improvement_metrics.original_failures_resolved < policy.min_failures_resolved:
                rejection_reasons.append(
                    f"Candidate failed to resolve sufficient target failures: "
                    f"resolved {improvement_metrics.original_failures_resolved}/{improvement_metrics.original_failures_total} "
                    f"(required minimum: {policy.min_failures_resolved})"
                )
            else:
                acceptance_reasons.append(
                    f"Candidate successfully resolved {improvement_metrics.original_failures_resolved} "
                    f"target failures ({improvement_metrics.resolution_rate:.1%})"
                )

        # Gate 5: Minimum Detection Rate (Recall)
        if candidate_metrics.recall < policy.min_detection_rate:
            rejection_reasons.append(
                f"Candidate detection rate {candidate_metrics.recall:.2%} is below required minimum "
                f"of {policy.min_detection_rate:.2%}"
            )
        else:
            acceptance_reasons.append(
                f"Candidate detection rate {candidate_metrics.recall:.2%} satisfies minimum (>= {policy.min_detection_rate:.2%})"
            )

        # Gate 6: Held-Out Split Generalization Gate
        held_out_key = DatasetSplitType.HELD_OUT.value
        if held_out_key in split_metrics:
            held_out = split_metrics[held_out_key]
            if held_out.total > 0 and held_out.f1 < policy.min_held_out_f1:
                rejection_reasons.append(
                    f"Held-out generalization F1 {held_out.f1:.2f} is below threshold {policy.min_held_out_f1:.2f}"
                )
            elif held_out.total > 0:
                acceptance_reasons.append(
                    f"Held-out generalization F1 {held_out.f1:.2f} satisfies threshold (>= {policy.min_held_out_f1:.2f})"
                )

        # Gate 7: Operational Latency Overhead & Error Budget
        if operational_metrics.error_count > 0:
            error_rate = operational_metrics.error_count / max(1, candidate_metrics.total)
            if error_rate > policy.max_error_rate:
                rejection_reasons.append(
                    f"Operational error rate {error_rate:.2%} exceeded maximum allowed {policy.max_error_rate:.2%}"
                )
        else:
            acceptance_reasons.append("Zero execution errors during audit evaluation")

        overhead = max(0.0, operational_metrics.mean_latency_ms)
        if overhead > policy.max_latency_overhead_ms:
            rejection_reasons.append(
                f"Operational latency {overhead:.2f}ms exceeded budget of {policy.max_latency_overhead_ms:.2f}ms"
            )
        else:
            acceptance_reasons.append(
                f"Operational latency {overhead:.2f}ms within budget (<= {policy.max_latency_overhead_ms:.2f}ms)"
            )

        # Determine final verdict
        if candidate_metrics.total == 0:
            verdict = EvaluationVerdict.INCONCLUSIVE
            status = EvaluationStatus.INCONCLUSIVE
            rationale = "Evaluation inconclusive: no scenarios evaluated"
        elif rejection_reasons:
            verdict = EvaluationVerdict.FAIL
            status = EvaluationStatus.REJECTED
            rationale = f"Candidate defense rejected: {'; '.join(rejection_reasons)}"
        else:
            verdict = EvaluationVerdict.PASS
            status = EvaluationStatus.ACCEPTED
            rationale = f"Candidate defense accepted: {'; '.join(acceptance_reasons[:3])}"

        return (verdict, status, rationale, acceptance_reasons, rejection_reasons)
