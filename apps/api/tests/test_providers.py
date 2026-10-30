"""Tests for AI provider abstractions, factory selection, and deterministic mock behavior."""

import pytest
from cyberduel_contracts.enums import Decision, EvaluationVerdict
from cyberduel_contracts.policy import CandidateDefense

from apps.api.app.providers.factory import get_ai_provider
from apps.api.app.providers.mock_provider import DeterministicMockProvider


@pytest.mark.asyncio
async def test_mock_provider_classifies_malicious() -> None:
    provider = DeterministicMockProvider()
    result = await provider.classify_resource(
        normalized_identifier="a" * 64,
        resource_url="https://secure-login.phish-bank.com",
    )
    assert result.decision == Decision.BLOCK
    assert result.threat_score >= 0.8
    assert len(result.evidence) >= 1
    assert result.evidence[0].category == "reputation"


@pytest.mark.asyncio
async def test_mock_provider_classifies_suspicious() -> None:
    provider = DeterministicMockProvider()
    result = await provider.classify_resource(
        normalized_identifier="b" * 64,
        resource_url="https://suspicious-domain-verification.org",
    )
    assert result.decision == Decision.WARN
    assert 0.4 <= result.threat_score <= 0.7


@pytest.mark.asyncio
async def test_mock_provider_classifies_benign() -> None:
    provider = DeterministicMockProvider()
    result = await provider.classify_resource(
        normalized_identifier="c" * 64,
        resource_url="https://legitimate-service.com",
    )
    assert result.decision == Decision.ALLOW
    assert result.threat_score < 0.2


@pytest.mark.asyncio
async def test_mock_provider_generates_scenario() -> None:
    provider = DeterministicMockProvider()
    scenario = await provider.generate_scenario(target_vulnerability="homograph_attack")
    assert scenario.expected_decision == Decision.BLOCK
    assert scenario.created_by_agent == "RedAI-Mock-v1"
    assert "safe_mode" in scenario.synthetic_payload


@pytest.mark.asyncio
async def test_mock_provider_evaluates_candidate() -> None:
    provider = DeterministicMockProvider()

    good_candidate = CandidateDefense(
        version="0.2.1-verified",
        author_agent="BlueAI-v1",
        description="Candidate with low FPR",
        rule_spec={"regex": r"paypal"},
    )
    good_eval = await provider.evaluate_candidate(good_candidate, "suite-phish-v1")
    assert good_eval.verdict == EvaluationVerdict.PASS
    assert good_eval.detection_rate >= 0.95

    failing_candidate = CandidateDefense(
        version="0.2.1-fail-regress",
        author_agent="BlueAI-v1",
        description="Candidate with regression",
        rule_spec={"regex": r".*"},
    )
    fail_eval = await provider.evaluate_candidate(failing_candidate, "suite-phish-v1")
    assert fail_eval.verdict == EvaluationVerdict.FAIL
    assert fail_eval.regression_count > 0


def test_provider_factory_returns_mock_by_default() -> None:
    provider = get_ai_provider()
    assert isinstance(provider, DeterministicMockProvider)
