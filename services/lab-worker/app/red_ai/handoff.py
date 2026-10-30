"""Evaluation Handoff service packaging laboratory findings for the Evaluator and Blue AI.

CRITICAL SEPARATION OF CONCERNS:
Red AI generates adversarial findings and packages them as candidate failure cases.
It does NOT approve defenses, mark hypotheses as verified facts, or modify production policies.
"""

from __future__ import annotations

from uuid import uuid4

from cyberduel_contracts.lab import (
    EvaluationHandoffPackage,
    ExperimentRunSummary,
    FailureFinding,
    ScenarioContract,
)


class EvaluationHandoff:
    """Constructs versioned audit packages for transmission to the Independent Evaluator and Blue AI."""

    @classmethod
    def create_package(
        cls,
        summary: ExperimentRunSummary,
        scenarios: list[ScenarioContract],
        findings: list[FailureFinding],
        ground_truth_confidence: float = 0.95,
    ) -> EvaluationHandoffPackage:
        """Construct an immutable evaluation handoff package from experiment outcomes."""
        # Find representative scenarios matching the findings
        failing_ids = set()
        for f in findings:
            failing_ids.update(f.representative_scenario_ids)

        rep_scenarios = [s for s in scenarios if s.scenario_id in failing_ids][:20]

        questions = [
            "Do the observed discrepancies represent novel evasion vectors or known policy limitations?",
            "Can declarative heuristic rules be synthesized to detect these patterns without elevating false positives on benign controls?",
            "What regression benchmarks must be evaluated before any proposed defensive update is considered for staging?",
        ]

        return EvaluationHandoffPackage(
            handoff_id=uuid4(),
            experiment_id=summary.experiment_id,
            candidate_id=uuid4(),
            detector_version=summary.detector_version,
            policy_version=summary.policy_version,
            total_failures=summary.discrepancy_count,
            findings=findings,
            representative_scenarios=rep_scenarios,
            ground_truth_confidence=ground_truth_confidence,
            reproduction_config={
                "seed": summary.seed,
                "goal": summary.goal,
                "scenario_count": summary.scenario_count,
            },
            suggested_investigation_questions=questions,
            status="handed_off",
        )
