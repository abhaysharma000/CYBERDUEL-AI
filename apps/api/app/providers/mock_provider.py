"""Deterministic mock implementation of AI model providers for local testing and CI."""

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from cyberduel_contracts.analysis import EvidenceItem, ThreatAnalysisResult
from cyberduel_contracts.enums import (
    Decision,
    EvaluationVerdict,
    ProvenanceType,
    ThreatSeverity,
)
from cyberduel_contracts.evaluation import EvaluationResult
from cyberduel_contracts.lab import LaboratoryScenario
from cyberduel_contracts.policy import CandidateDefense

from apps.api.app.providers.base import (
    BaseEvaluationProvider,
    BaseReasoningProvider,
    BaseScenarioGeneratorProvider,
    BaseThreatClassificationProvider,
)


class DeterministicMockProvider(
    BaseReasoningProvider,
    BaseThreatClassificationProvider,
    BaseScenarioGeneratorProvider,
    BaseEvaluationProvider,
):
    """Offline, deterministic AI provider that produces predictable outputs without API keys."""

    def __init__(self, model_name: str = "deterministic-mock-v1") -> None:
        self.model_name = model_name

    async def generate_response(
        self,
        prompt: str,
        system_instruction: str = "",
        temperature: float = 0.2,
    ) -> str:
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:8]
        return (
            f"[DeterministicMockResponse:{self.model_name}] Processed prompt (hash={prompt_hash}): "
            "Defensive analysis completed with simulated reasoning."
        )

    async def classify_resource(
        self,
        normalized_identifier: str,
        resource_url: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> ThreatAnalysisResult:
        query_str = (resource_url or normalized_identifier).lower()

        evidence: list[EvidenceItem] = []
        if "malicious" in query_str or "phish" in query_str or "evil" in query_str:
            threat_score = 0.92
            decision = Decision.BLOCK
            evidence.append(
                EvidenceItem(
                    category="reputation",
                    reason="Target indicator matched synthetic malicious signature blacklist",
                    severity=ThreatSeverity.CRITICAL,
                    confidence=0.98,
                )
            )
        elif "suspicious" in query_str or "warn" in query_str or "login" in query_str:
            threat_score = 0.55
            decision = Decision.WARN
            evidence.append(
                EvidenceItem(
                    category="heuristic",
                    reason="Target displays deceptive visual or lexical mimicry traits",
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.75,
                )
            )
        else:
            threat_score = 0.05
            decision = Decision.ALLOW
            evidence.append(
                EvidenceItem(
                    category="baseline",
                    reason="No anomalies detected across reputation or behavioral heuristics",
                    severity=ThreatSeverity.NONE,
                    confidence=0.90,
                )
            )

        return ThreatAnalysisResult(
            analysis_id=uuid4(),
            normalized_identifier=normalized_identifier,
            threat_score=threat_score,
            decision=decision,
            evidence=evidence,
            engine_version="0.1.0-mock",
            policy_version="2026.10.1",
            confidence=0.95,
            provenance=ProvenanceType.MODEL_INFERENCE,
            created_at=datetime.now(UTC),
        )

    async def generate_scenario(
        self,
        target_vulnerability: str,
        difficulty: str = "intermediate",
    ) -> LaboratoryScenario:
        valid_difficulty = (
            difficulty
            if difficulty in ["basic", "intermediate", "advanced", "adversarial"]
            else "intermediate"
        )
        return LaboratoryScenario(
            scenario_id=uuid4(),
            title=f"Synthetic test challenge for {target_vulnerability}",
            scenario_type=target_vulnerability,
            synthetic_payload={
                "domain": "secure-payment-verification.example-synthetic.com",
                "features": ["idna_homograph", "punycode_encoded"],
                "safe_mode": True,
            },
            expected_decision=Decision.BLOCK,
            difficulty=valid_difficulty,  # type: ignore[arg-type]
            created_by_agent="RedAI-Mock-v1",
        )

    async def evaluate_candidate(
        self,
        candidate: CandidateDefense,
        scenario_suite_id: str,
    ) -> EvaluationResult:
        # Candidate versions with 'fail' in their name simulate rejected models
        will_pass = "fail" not in candidate.version.lower()
        return EvaluationResult(
            evaluation_id=uuid4(),
            candidate_defense_id=candidate.defense_id,
            scenario_suite_id=scenario_suite_id,
            total_scenarios=100,
            passed_scenarios=99 if will_pass else 60,
            detection_rate=0.99 if will_pass else 0.60,
            false_positive_rate=0.01 if will_pass else 0.15,
            regression_count=0 if will_pass else 5,
            resource_overhead_ms=1.45,
            verdict=EvaluationVerdict.PASS if will_pass else EvaluationVerdict.FAIL,
            verdict_rationale=(
                "Passed benchmark without regressions."
                if will_pass
                else "Excessive false positives and regressions detected on known benign corpora."
            ),
        )
