"""Defensive Test Runner executing synthetic scenarios directly against the URLAnalysisService."""

from __future__ import annotations

import logging
import time
from uuid import UUID, uuid4

from cyberduel_contracts.enums import Decision, DiscrepancyType, ExpectedClass
from cyberduel_contracts.lab import ScenarioContract, ScenarioExecutionResult
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.services.url_analysis_service import URLAnalysisService

logger = logging.getLogger("defensive_runner")


class DefensiveTestRunner:
    """Executes synthetic threat scenarios directly through the live defensive analysis pipeline."""

    def __init__(self, session: AsyncSession | None = None) -> None:
        self.session = session
        self.analysis_service = URLAnalysisService(session=session)

    async def execute_scenario(
        self,
        scenario: ScenarioContract,
        experiment_id: UUID,
    ) -> ScenarioExecutionResult:
        """Run a single scenario through the URL analysis service and record the exact observation."""
        raw_url = str(scenario.input_fixture.get("raw_url", ""))
        start_time = time.perf_counter()

        try:
            analysis_result = await self.analysis_service.analyze_url(raw_url=raw_url)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            actual_decision = analysis_result.decision
            actual_score = analysis_result.threat_score
            actual_evidence = [
                {
                    "category": e.category,
                    "reason": e.reason,
                    "severity": e.severity.value,
                    "confidence": e.confidence,
                }
                for e in analysis_result.evidence
            ]
            detector_version = analysis_result.engine_version
            policy_version = analysis_result.policy_version

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(
                f"Error during defensive inspection of scenario {scenario.scenario_id}: {exc}"
            )
            actual_decision = Decision.WARN
            actual_score = 0.50
            actual_evidence = [
                {"category": "runner_error", "reason": str(exc), "severity": "medium"}
            ]
            detector_version = URLAnalysisService.ENGINE_VERSION
            policy_version = URLAnalysisService.POLICY_VERSION

        # Evaluate discrepancy between expected ground truth and actual defensive response
        is_discrepancy, discrepancy_type = self._classify_discrepancy(
            expected_class=scenario.expected_class,
            expected_decision=scenario.expected_decision,
            actual_decision=actual_decision,
            actual_score=actual_score,
        )

        return ScenarioExecutionResult(
            execution_id=uuid4(),
            experiment_id=experiment_id,
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.scenario_name,
            scenario_family=scenario.scenario_family,
            raw_url=raw_url,
            expected_class=scenario.expected_class,
            expected_decision=scenario.expected_decision,
            actual_decision=actual_decision,
            actual_threat_score=actual_score,
            actual_evidence=actual_evidence,
            detector_version=detector_version,
            policy_version=policy_version,
            is_discrepancy=is_discrepancy,
            discrepancy_type=discrepancy_type.value,
            duration_ms=duration_ms,
        )

    def _classify_discrepancy(
        self,
        expected_class: str,
        expected_decision: Decision,
        actual_decision: Decision,
        actual_score: float,
    ) -> tuple[bool, DiscrepancyType]:
        """Determine whether the engine decision deviates meaningfully from expected ground truth."""
        # 1. Uncertain cases are never marked as errors/discrepancies unless a severe unhandled error occurs
        if expected_class == ExpectedClass.UNCERTAIN.value:
            return False, DiscrepancyType.UNCERTAIN_OUTCOME

        # 2. Perfect match
        if actual_decision == expected_decision:
            return False, DiscrepancyType.NONE

        # 3. False Positive: Benign ground truth flagged as block or warn
        if expected_class == ExpectedClass.BENIGN.value and actual_decision in {
            Decision.BLOCK,
            Decision.WARN,
        }:
            return True, DiscrepancyType.FALSE_POSITIVE

        # 4. False Negative: Malicious ground truth treated as allow
        if expected_class == ExpectedClass.MALICIOUS.value:
            if actual_decision == Decision.ALLOW:
                return True, DiscrepancyType.FALSE_NEGATIVE
            if actual_decision == Decision.WARN:
                # Underconfident detection
                return True, DiscrepancyType.UNDERCONFIDENT

        # 5. Overly Aggressive: Expected warn, but produced block
        if expected_decision == Decision.WARN and actual_decision == Decision.BLOCK:
            return True, DiscrepancyType.OVERLY_AGGRESSIVE

        # 6. Underconfident: Expected block, but produced warn
        if expected_decision == Decision.BLOCK and actual_decision == Decision.WARN:
            return True, DiscrepancyType.UNDERCONFIDENT

        return True, DiscrepancyType.UNCERTAIN_OUTCOME
