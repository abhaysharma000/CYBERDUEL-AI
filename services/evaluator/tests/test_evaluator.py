"""Tests for independent benchmark evaluator."""

import pytest
from cyberduel_contracts.enums import EvaluationVerdict
from cyberduel_contracts.policy import CandidateDefense

from services.evaluator.app.evaluator import BenchmarkEvaluator


@pytest.mark.asyncio
async def test_evaluator_passes_good_candidate() -> None:
    evaluator = BenchmarkEvaluator()
    candidate = CandidateDefense(
        version="0.2.0-candidate",
        author_agent="BlueAI-v1",
        description="Improved homograph regex rule",
        rule_spec={"regex": r"paypal.*[0-9]"},
    )
    result = await evaluator.evaluate_candidate(candidate)
    assert result.verdict == EvaluationVerdict.PASS
    assert result.detection_rate >= 0.95
    assert result.regression_count == 0


@pytest.mark.asyncio
async def test_evaluator_rejects_regressing_candidate() -> None:
    evaluator = BenchmarkEvaluator()
    candidate = CandidateDefense(
        version="0.2.0-fail-test",
        author_agent="BlueAI-v1",
        description="Overly broad rule causing false positives",
        rule_spec={"regex": r".*"},
    )
    result = await evaluator.evaluate_candidate(candidate)
    assert result.verdict == EvaluationVerdict.FAIL
    assert result.regression_count > 0
