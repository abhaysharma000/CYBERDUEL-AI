"""Candidate sandbox runner service for Blue AI.

Executes side-by-side comparative audits of candidate defenses against baseline detectors
without mutating production state, evaluating regressions, resolved failures, and FPR.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from cyberduel_contracts.enums import Decision, ExpectedClass
from cyberduel_contracts.lab import ScenarioContract
from cyberduel_contracts.policy import (
    BaselineComparisonReport,
    CandidateDefense,
    DeclarativeRuleModel,
)
from cyberduel_policy_engine.sandbox import (
    CandidateDetectorSandbox,
    SandboxEvaluationOutcome,
)
from cyberduel_threat_intel.scoring import ScoringPolicyConfig
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.policies import SandboxComparisonRecord

logger = logging.getLogger("blue_ai.sandbox_runner")


class CandidateSandboxRunner:
    """Executes isolated comparative evaluations between candidate defenses and active baseline."""

    # Curated benign controls to evaluate false positive rates
    STANDARD_BENIGN_CONTROLS = [
        ("https://www.google.com/search?q=cyberduel", ExpectedClass.BENIGN.value, Decision.ALLOW),
        ("https://github.com/microsoft/vscode", ExpectedClass.BENIGN.value, Decision.ALLOW),
        ("https://en.wikipedia.org/wiki/Phishing", ExpectedClass.BENIGN.value, Decision.ALLOW),
        ("https://apple.com/iphone", ExpectedClass.BENIGN.value, Decision.ALLOW),
        ("https://aws.amazon.com/console/", ExpectedClass.BENIGN.value, Decision.ALLOW),
        ("https://docs.python.org/3/", ExpectedClass.BENIGN.value, Decision.ALLOW),
        ("https://www.cloudflare.com/learning/ssl/", ExpectedClass.BENIGN.value, Decision.ALLOW),
        ("https://developer.mozilla.org/en-US/", ExpectedClass.BENIGN.value, Decision.ALLOW),
    ]

    # Curated regression benchmarks to ensure existing attack detection isn't weakened
    STANDARD_REGRESSION_BENCHMARKS = [
        ("http://192.168.1.1/login.php", ExpectedClass.MALICIOUS.value, Decision.BLOCK),
        (
            "https://paypal-update-account-security.com/login",
            ExpectedClass.MALICIOUS.value,
            Decision.BLOCK,
        ),
        ("https://microsoft-verify-login.xyz/auth", ExpectedClass.MALICIOUS.value, Decision.BLOCK),
        (
            "http://secure-banking-portal-verification.top/signin",
            ExpectedClass.MALICIOUS.value,
            Decision.BLOCK,
        ),
    ]

    @classmethod
    def _parse_candidate_rules(cls, candidate: CandidateDefense) -> list[DeclarativeRuleModel]:
        """Extract and instantiate DeclarativeRuleModel objects from CandidateDefense rule_spec."""
        rules_data = candidate.rule_spec.get("rules", [])
        rules: list[DeclarativeRuleModel] = []
        for r_dict in rules_data:
            try:
                rule = DeclarativeRuleModel.model_validate(r_dict)
                rules.append(rule)
            except Exception as e:
                logger.warning(f"Failed to deserialize candidate rule: {e}")
        return rules

    @classmethod
    async def run_comparison(
        cls,
        candidate: CandidateDefense,
        failing_scenarios: list[ScenarioContract] | None = None,
        extra_benign_urls: list[str] | None = None,
        session: AsyncSession | None = None,
    ) -> BaselineComparisonReport:
        """Run full side-by-side comparative evaluation of candidate defense vs baseline."""
        rules = cls._parse_candidate_rules(candidate)
        tuning = candidate.rule_spec.get("tuning")

        scoring_config = None
        if tuning and isinstance(tuning, dict):
            warn_val = tuning.get("warn_threshold") or tuning.get("suspicious_threshold") or 0.35
            block_val = tuning.get("block_threshold") or tuning.get("malicious_threshold") or 0.70
            scoring_config = ScoringPolicyConfig(
                warn_threshold=float(warn_val),
                block_threshold=float(block_val),
            )

        sandbox = CandidateDetectorSandbox(
            candidate_rules=rules,
            candidate_scoring_config=scoring_config,
        )

        test_items: list[tuple[str, str, Decision, str]] = []

        # 1. Failing scenarios from Red AI
        if failing_scenarios:
            for s in failing_scenarios:
                if s.input_fixture:
                    raw_u = (
                        s.input_fixture.get("raw_url", "")
                        if isinstance(s.input_fixture, dict)
                        else getattr(s.input_fixture, "raw_url", "")
                    )
                    if raw_u:
                        test_items.append(
                            (
                                raw_u,
                                s.expected_class.value
                                if hasattr(s.expected_class, "value")
                                else str(s.expected_class),
                                s.expected_decision
                                if isinstance(s.expected_decision, Decision)
                                else Decision(s.expected_decision),
                                s.scenario_family.value
                                if hasattr(s.scenario_family, "value")
                                else str(s.scenario_family),
                            )
                        )

        # 2. Standard Benign Controls
        for url, exp_class, exp_dec in cls.STANDARD_BENIGN_CONTROLS:
            test_items.append((url, exp_class, exp_dec, "benign_control"))

        if extra_benign_urls:
            for b_url in extra_benign_urls:
                test_items.append(
                    (b_url, ExpectedClass.BENIGN.value, Decision.ALLOW, "benign_control")
                )

        # 3. Standard Regression Benchmarks
        for url, exp_class, exp_dec in cls.STANDARD_REGRESSION_BENCHMARKS:
            test_items.append((url, exp_class, exp_dec, "regression_benchmark"))

        # Execute all tests through sandbox
        outcomes: list[tuple[SandboxEvaluationOutcome, str]] = []
        for url, exp_class, exp_dec, family in test_items:
            outcome = await sandbox.evaluate_url(
                raw_url=url,
                expected_class=exp_class,
                expected_decision=exp_dec,
            )
            outcomes.append((outcome, family))

        # Metric aggregation
        total_tests = len(outcomes)
        b_correct = sum(1 for o, _ in outcomes if o.baseline_decision == o.expected_decision)
        c_correct = sum(1 for o, _ in outcomes if o.candidate_decision == o.expected_decision)

        # Malicious targets
        mal_outcomes = [
            (o, f) for o, f in outcomes if o.expected_class == ExpectedClass.MALICIOUS.value
        ]
        total_mal = len(mal_outcomes) or 1
        b_mal_detected = sum(
            1 for o, _ in mal_outcomes if o.baseline_decision in {Decision.WARN, Decision.BLOCK}
        )
        c_mal_detected = sum(
            1 for o, _ in mal_outcomes if o.candidate_decision in {Decision.WARN, Decision.BLOCK}
        )

        # Benign targets
        ben_outcomes = [
            (o, f) for o, f in outcomes if o.expected_class == ExpectedClass.BENIGN.value
        ]
        total_ben = len(ben_outcomes) or 1
        b_fp = sum(
            1 for o, _ in ben_outcomes if o.baseline_decision in {Decision.WARN, Decision.BLOCK}
        )
        c_fp = sum(
            1 for o, _ in ben_outcomes if o.candidate_decision in {Decision.WARN, Decision.BLOCK}
        )

        # Calculations
        baseline_acc = round(b_correct / total_tests, 4) if total_tests else 0.0
        candidate_acc = round(c_correct / total_tests, 4) if total_tests else 0.0

        baseline_recall = round(b_mal_detected / total_mal, 4)
        candidate_recall = round(c_mal_detected / total_mal, 4)

        baseline_fpr = round(b_fp / total_ben, 4)
        candidate_fpr = round(c_fp / total_ben, 4)

        # F1 approximate
        b_prec = b_mal_detected / (b_mal_detected + b_fp) if (b_mal_detected + b_fp) else 1.0
        c_prec = c_mal_detected / (c_mal_detected + c_fp) if (c_mal_detected + c_fp) else 1.0
        baseline_f1 = (
            round(2 * (b_prec * baseline_recall) / (b_prec + baseline_recall), 4)
            if (b_prec + baseline_recall)
            else 0.0
        )
        candidate_f1 = (
            round(2 * (c_prec * candidate_recall) / (c_prec + candidate_recall), 4)
            if (c_prec + candidate_recall)
            else 0.0
        )

        # Detailed counts
        original_fixed = sum(1 for o, _ in outcomes if o.candidate_fixed_failure)
        new_regressions = sum(1 for o, _ in outcomes if o.is_regression)
        new_false_positives = sum(1 for o, _ in outcomes if o.is_new_false_positive)

        # Family breakdown
        family_map: dict[str, dict[str, Any]] = {}
        for o, fam in outcomes:
            if fam not in family_map:
                family_map[fam] = {
                    "total": 0,
                    "baseline_correct": 0,
                    "candidate_correct": 0,
                    "fixed": 0,
                    "regressions": 0,
                }
            f_entry = family_map[fam]
            f_entry["total"] += 1
            if o.baseline_decision == o.expected_decision:
                f_entry["baseline_correct"] += 1
            if o.candidate_decision == o.expected_decision:
                f_entry["candidate_correct"] += 1
            if o.candidate_fixed_failure:
                f_entry["fixed"] += 1
            if o.is_regression:
                f_entry["regressions"] += 1

        # Verdict assignment
        verdict: Literal["promoted_for_evaluation", "rejected_regressive", "inconclusive"]
        if new_regressions > 0 or candidate_fpr > 0.08:
            verdict = "rejected_regressive"
            trade_off = (
                f"Candidate rejected: {new_regressions} regressions detected, "
                f"Candidate FPR={candidate_fpr:.2%} (limit 8.0%)."
            )
        elif new_regressions == 0 and candidate_fpr <= 0.05 and original_fixed > 0:
            verdict = "promoted_for_evaluation"
            trade_off = (
                f"Candidate promoted: Fixed {original_fixed} prior detection failures with "
                f"0 regressions and healthy FPR={candidate_fpr:.2%} (Recall: {baseline_recall:.1%} -> {candidate_recall:.1%})."
            )
        else:
            verdict = "inconclusive"
            trade_off = (
                f"Candidate inconclusive: Fixed {original_fixed} failures, "
                f"{new_regressions} regressions, candidate FPR={candidate_fpr:.2%}."
            )

        report = BaselineComparisonReport(
            comparison_id=uuid4(),
            candidate_id=candidate.defense_id,
            candidate_version=candidate.version,
            baseline_version="1.0.0",
            total_scenarios_evaluated=total_tests,
            baseline_accuracy=baseline_acc,
            candidate_accuracy=candidate_acc,
            baseline_recall=baseline_recall,
            candidate_recall=candidate_recall,
            baseline_fpr=baseline_fpr,
            candidate_fpr=candidate_fpr,
            baseline_f1=baseline_f1,
            candidate_f1=candidate_f1,
            original_failures_resolved=original_fixed,
            new_regressions=new_regressions,
            new_false_positives=new_false_positives,
            family_breakdown=family_map,
            trade_off_analysis=trade_off,
            preliminary_verdict=verdict,
            created_at=datetime.now(UTC),
        )

        # Save to DB if session provided
        if session is not None:
            record = SandboxComparisonRecord(
                id=report.comparison_id,
                candidate_id=report.candidate_id,
                candidate_version=report.candidate_version,
                baseline_version=report.baseline_version,
                total_scenarios=report.total_scenarios_evaluated,
                original_failures_resolved=report.original_failures_resolved,
                new_regressions=report.new_regressions,
                new_false_positives=report.new_false_positives,
                baseline_accuracy=report.baseline_accuracy,
                candidate_accuracy=report.candidate_accuracy,
                baseline_recall=report.baseline_recall,
                candidate_recall=report.candidate_recall,
                baseline_fpr=report.baseline_fpr,
                candidate_fpr=report.candidate_fpr,
                preliminary_verdict=report.preliminary_verdict,
                report_payload=report.model_dump(mode="json"),
                created_at=report.created_at,
                updated_at=report.created_at,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)

        return report
