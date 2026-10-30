"""Rigorous metrics computation engine for independent cybersecurity evaluation."""

import math
from typing import Any
from uuid import UUID

from cyberduel_contracts.enums import Decision, ExpectedClass
from cyberduel_contracts.evaluation import (
    ConfusionMatrix,
    ImprovementMetrics,
    OperationalMetrics,
)


class MetricsEngine:
    """Computes exact classification, improvement deltas, and operational benchmarks."""

    @staticmethod
    def is_positive_detection(decision: Decision | str) -> bool:
        """Return True if decision acts to mitigate or flag threat (block or warn)."""
        dec_val = decision.value if isinstance(decision, Decision) else str(decision).lower()
        return dec_val in {Decision.BLOCK.value, Decision.WARN.value}

    @staticmethod
    def is_ground_truth_threat(expected_class: ExpectedClass | str) -> bool:
        """Return True if ground truth is malicious or suspicious."""
        cls_val = (
            expected_class.value
            if isinstance(expected_class, ExpectedClass)
            else str(expected_class).lower()
        )
        return cls_val in {ExpectedClass.MALICIOUS.value, ExpectedClass.SUSPICIOUS.value}

    @staticmethod
    def is_ground_truth_benign(expected_class: ExpectedClass | str) -> bool:
        """Return True if ground truth is benign."""
        cls_val = (
            expected_class.value
            if isinstance(expected_class, ExpectedClass)
            else str(expected_class).lower()
        )
        return cls_val == ExpectedClass.BENIGN.value

    @classmethod
    def compute_confusion_matrix(cls, records: list[dict[str, Any]]) -> ConfusionMatrix:
        """Calculate TP, FP, TN, FN across executed scenario evaluation records."""
        tp = 0
        fp = 0
        tn = 0
        fn = 0

        for rec in records:
            actual_dec = rec.get("actual_decision", Decision.ALLOW)
            exp_class = rec.get("expected_class", ExpectedClass.BENIGN)

            is_pos = cls.is_positive_detection(actual_dec)
            is_threat = cls.is_ground_truth_threat(exp_class)
            is_benign = cls.is_ground_truth_benign(exp_class)

            if is_threat:
                if is_pos:
                    tp += 1
                else:
                    fn += 1
            elif is_benign:
                if is_pos:
                    fp += 1
                else:
                    tn += 1
            else:
                # Neutral / uncertain
                pass

        return ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn)

    @classmethod
    def compute_operational_metrics(
        cls,
        durations_ms: list[float],
        error_count: int = 0,
        timeout_count: int = 0,
    ) -> OperationalMetrics:
        """Calculate operational latency percentiles and error metrics."""
        if not durations_ms:
            return OperationalMetrics(
                total_duration_ms=0.0,
                mean_latency_ms=0.0,
                p95_latency_ms=0.0,
                max_latency_ms=0.0,
                error_count=error_count,
                timeout_count=timeout_count,
            )

        sorted_durations = sorted(durations_ms)
        total_duration = sum(sorted_durations)
        mean_latency = total_duration / len(sorted_durations)
        max_latency = sorted_durations[-1]

        # Calculate P95
        p95_index = math.ceil(0.95 * len(sorted_durations)) - 1
        p95_index = max(0, min(p95_index, len(sorted_durations) - 1))
        p95_latency = sorted_durations[p95_index]

        return OperationalMetrics(
            total_duration_ms=round(total_duration, 2),
            mean_latency_ms=round(mean_latency, 2),
            p95_latency_ms=round(p95_latency, 2),
            max_latency_ms=round(max_latency, 2),
            error_count=error_count,
            timeout_count=timeout_count,
        )

    @classmethod
    def compute_improvement_metrics(
        cls,
        baseline_records: list[dict[str, Any]],
        candidate_records: list[dict[str, Any]],
        target_scenario_ids: set[UUID] | None = None,
    ) -> ImprovementMetrics:
        """Calculate delta improvements, failure resolutions, regressions, and family breakdown."""
        baseline_by_id: dict[Any, dict[str, Any]] = {
            rec["scenario_id"]: rec for rec in baseline_records
        }
        candidate_by_id: dict[Any, dict[str, Any]] = {
            rec["scenario_id"]: rec for rec in candidate_records
        }

        common_ids = set(baseline_by_id.keys()).intersection(candidate_by_id.keys())

        failures_resolved = 0
        failures_total = 0
        new_regressions = 0
        new_false_positives = 0

        family_stats: dict[str, dict[str, Any]] = {}

        for sc_id in common_ids:
            b_rec = baseline_by_id[sc_id]
            c_rec = candidate_by_id[sc_id]

            exp_cls = b_rec.get("expected_class", ExpectedClass.BENIGN)
            family = str(b_rec.get("scenario_family", "unknown"))

            b_correct = cls._is_correct(b_rec["actual_decision"], exp_cls)
            c_correct = cls._is_correct(c_rec["actual_decision"], exp_cls)

            # Family breakdown tracking
            f_stat = family_stats.setdefault(
                family,
                {
                    "total": 0,
                    "baseline_correct": 0,
                    "candidate_correct": 0,
                    "resolved": 0,
                    "regressed": 0,
                },
            )
            f_stat["total"] += 1
            if b_correct:
                f_stat["baseline_correct"] += 1
            if c_correct:
                f_stat["candidate_correct"] += 1

            # Target failure resolution tracking
            is_target = target_scenario_ids is None or sc_id in target_scenario_ids
            if is_target and not b_correct:
                failures_total += 1
                if c_correct:
                    failures_resolved += 1
                    f_stat["resolved"] += 1

            # Regression tracking: baseline was correct, candidate is now wrong
            if b_correct and not c_correct:
                new_regressions += 1
                f_stat["regressed"] += 1
                # If benign was flagged as threat, that is also a new false positive
                if cls.is_ground_truth_benign(exp_cls) and cls.is_positive_detection(
                    c_rec["actual_decision"]
                ):
                    new_false_positives += 1

        b_matrix = cls.compute_confusion_matrix(list(baseline_by_id.values()))
        c_matrix = cls.compute_confusion_matrix(list(candidate_by_id.values()))

        resolution_rate = (
            round(failures_resolved / failures_total, 4) if failures_total > 0 else 1.0
        )
        delta_f1 = round(c_matrix.f1 - b_matrix.f1, 4)
        delta_recall = round(c_matrix.recall - b_matrix.recall, 4)
        delta_fpr = round(c_matrix.false_positive_rate - b_matrix.false_positive_rate, 4)

        return ImprovementMetrics(
            original_failures_resolved=failures_resolved,
            original_failures_total=failures_total,
            resolution_rate=resolution_rate,
            new_regressions=new_regressions,
            new_false_positives=new_false_positives,
            delta_f1=delta_f1,
            delta_recall=delta_recall,
            delta_fpr=delta_fpr,
            family_breakdown=family_stats,
        )

    @classmethod
    def _is_correct(cls, decision: Decision | str, expected_class: ExpectedClass | str) -> bool:
        """Check whether a decision accurately matches expected classification."""
        is_pos = cls.is_positive_detection(decision)
        if cls.is_ground_truth_threat(expected_class):
            return is_pos
        if cls.is_ground_truth_benign(expected_class):
            return not is_pos
        return True
