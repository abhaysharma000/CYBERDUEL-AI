"""Candidate Detector Sandbox for testing candidate defense modifications without mutating baseline policy."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from cyberduel_contracts.analysis import EvidenceItem
from cyberduel_contracts.enums import Decision, ExpectedClass
from cyberduel_contracts.policy import DeclarativeRuleModel
from cyberduel_threat_intel.scoring import RiskScoringEngine, ScoringPolicyConfig
from cyberduel_threat_intel.validator import URLValidator

from cyberduel_policy_engine.rules import DeclarativeRuleEngine

logger = logging.getLogger("candidate_sandbox")


@dataclass(frozen=True)
class SandboxEvaluationOutcome:
    """Side-by-side outcome of baseline versus candidate evaluation on a single URL."""

    raw_url: str
    expected_class: str
    expected_decision: Decision
    baseline_decision: Decision
    baseline_score: float
    candidate_decision: Decision
    candidate_score: float
    candidate_fixed_failure: bool
    is_regression: bool
    is_new_false_positive: bool
    baseline_evidence: list[str]
    candidate_evidence: list[str]
    candidate_rules_triggered: list[str]


class CandidateDetectorSandbox:
    """Executes candidate defense rules and policies alongside baseline detector in strict isolation."""

    def __init__(
        self,
        candidate_rules: list[DeclarativeRuleModel] | None = None,
        candidate_scoring_config: ScoringPolicyConfig | None = None,
        baseline_service: Any = None,
    ) -> None:
        self.candidate_rules = candidate_rules or []
        if baseline_service is not None:
            self.baseline_service = baseline_service
        else:
            from apps.api.app.services.url_analysis_service import URLAnalysisService

            self.baseline_service = URLAnalysisService(session=None)
        self.candidate_scoring_engine = RiskScoringEngine(config=candidate_scoring_config)

    async def evaluate_url(
        self,
        raw_url: str,
        expected_class: str = ExpectedClass.MALICIOUS.value,
        expected_decision: Decision = Decision.BLOCK,
    ) -> SandboxEvaluationOutcome:
        """Run candidate defense alongside baseline on a URL and record comparative differences."""
        # 1. Baseline Evaluation
        baseline_res = await self.baseline_service.analyze_url(raw_url=raw_url)

        # 2. Candidate Evaluation
        val_res = URLValidator.validate(raw_url)
        if not val_res.is_valid or not val_res.normalized:
            # URL rejected by validator
            candidate_decision = Decision.ALLOW
            candidate_score = 0.0
            candidate_evidence: list[EvidenceItem] = []
            candidate_rules_triggered: list[str] = []
        else:
            url = val_res.normalized

            # Start with baseline heuristic evidence
            heuristic_evidence = list(self.baseline_service.heuristic_analyzer.analyze(url))
            candidate_rules_triggered = []

            # Evaluate candidate declarative rules
            for rule in self.candidate_rules:
                outcome = DeclarativeRuleEngine.evaluate_rule(rule, url)
                if outcome.matched and outcome.evidence:
                    heuristic_evidence.append(outcome.evidence)
                    candidate_rules_triggered.append(rule.rule_id)

            is_whitelisted = self.baseline_service.heuristic_analyzer._is_whitelisted(url)

            # Re-score with candidate evidence
            scoring = self.candidate_scoring_engine.evaluate(
                indicator_matches=[],
                heuristic_evidence=heuristic_evidence,
                is_whitelisted=is_whitelisted,
            )

            candidate_decision = scoring.decision
            candidate_score = scoring.threat_score
            candidate_evidence = scoring.evidence

        # 3. Analyze Trade-offs & Regressions
        # Fixed failure: Baseline was incorrect, candidate matched expected decision
        baseline_was_incorrect = baseline_res.decision != expected_decision
        candidate_is_correct = candidate_decision == expected_decision
        fixed = baseline_was_incorrect and candidate_is_correct

        # Regression: Baseline was correct, but candidate deviated to incorrect decision
        baseline_was_correct = baseline_res.decision == expected_decision
        candidate_is_incorrect = candidate_decision != expected_decision
        regression = baseline_was_correct and candidate_is_incorrect

        # New False Positive: Ground truth is benign, baseline allowed it, candidate blocked or warned
        new_fp = (
            expected_class == ExpectedClass.BENIGN.value
            and baseline_res.decision == Decision.ALLOW
            and candidate_decision in {Decision.BLOCK, Decision.WARN}
        )

        return SandboxEvaluationOutcome(
            raw_url=raw_url,
            expected_class=expected_class,
            expected_decision=expected_decision,
            baseline_decision=baseline_res.decision,
            baseline_score=baseline_res.threat_score,
            candidate_decision=candidate_decision,
            candidate_score=candidate_score,
            candidate_fixed_failure=fixed,
            is_regression=regression,
            is_new_false_positive=new_fp,
            baseline_evidence=[e.reason for e in baseline_res.evidence],
            candidate_evidence=[e.reason for e in candidate_evidence],
            candidate_rules_triggered=candidate_rules_triggered,
        )
