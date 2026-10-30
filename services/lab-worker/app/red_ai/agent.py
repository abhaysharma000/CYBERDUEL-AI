"""Red AI Research Agent orchestrating the 8-step adversarial laboratory testing workflow.

Executes controlled, reproducible experiments against the defensive engine, categorizes detection
gaps, and packages findings for the independent evaluator without external cloud dependencies.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID, uuid4

from cyberduel_contracts.lab import (
    EvaluationHandoffPackage,
    ExperimentConfig,
    ExperimentRunSummary,
    ScenarioContract,
    ScenarioExecutionResult,
)
from sqlalchemy.ext.asyncio import AsyncSession

from services.lab_worker.app.red_ai.analyzer import FailureAnalyzer
from services.lab_worker.app.red_ai.generator import ScenarioGenerator
from services.lab_worker.app.red_ai.handoff import EvaluationHandoff
from services.lab_worker.app.red_ai.recorder import ExperimentRecorder
from services.lab_worker.app.red_ai.runner import DefensiveTestRunner
from services.lab_worker.app.red_ai.validator import ScenarioValidator

logger = logging.getLogger("red_research_agent")


class RedResearchAgent:
    """Autonomous adversarial laboratory research agent implementing the 8-step testing workflow."""

    AGENT_VERSION = "0.3.0-red-lab"

    def __init__(self, session: AsyncSession | None = None) -> None:
        self.session = session
        self.test_runner = DefensiveTestRunner(session=session)
        self.recorder = ExperimentRecorder(session=session)

    async def run_experiment(
        self,
        config: ExperimentConfig,
        experiment_id: UUID | None = None,
    ) -> tuple[ExperimentRunSummary, EvaluationHandoffPackage, list[ScenarioExecutionResult]]:
        """Execute complete 8-step adversarial research workflow."""
        exp_id = experiment_id or uuid4()
        started_at = datetime.now(UTC)
        logger.info(
            f"Starting Red AI experiment {exp_id} - '{config.experiment_name}' [Seed: {config.seed}]"
        )

        # Step 1: Select Experiment Goal & Initialize Configuration
        goal = config.goal

        # Step 2: Generate Synthetic Scenarios (via QwenProvider if configured, else procedural)
        generator = ScenarioGenerator(seed=config.seed)
        raw_scenarios = await generator.generate_corpus_async(
            count=config.scenario_count,
            families=config.selected_families if config.selected_families else None,
            mutation_depth=config.mutation_depth,
            goal=goal,
            experiment_id=exp_id,
        )

        # Step 3: Validate Scenarios against Safety & Structural Bounds
        validated_scenarios: list[ScenarioContract] = []
        for sc in raw_scenarios:
            val_res = ScenarioValidator.validate(sc)
            if val_res.is_valid:
                validated_scenarios.append(sc)
            else:
                logger.warning(
                    f"Scenario {sc.scenario_id} rejected by validator: {val_res.error_message}"
                )

        # Persist experiment record and scenarios
        await self.recorder.create_experiment(
            experiment_id=exp_id,
            config=config,
            scenario_count=len(validated_scenarios),
        )
        await self.recorder.persist_scenarios(
            experiment_id=exp_id,
            scenarios=validated_scenarios,
        )

        # Step 4: Run Current Detector Pipeline
        executions: list[ScenarioExecutionResult] = []
        for sc in validated_scenarios:
            exec_result = await self.test_runner.execute_scenario(sc, experiment_id=exp_id)
            executions.append(exec_result)

        # Step 5: Analyze Discrepancies
        findings = FailureAnalyzer.analyze_executions(
            experiment_id=exp_id,
            executions=executions,
        )

        # Step 6: Identify Promising Test Gaps & Compute Aggregate Metrics
        metrics = FailureAnalyzer.compute_metrics(executions)
        discrepancy_count = sum(1 for e in executions if e.is_discrepancy)

        # Step 7: Produce Experiment Report
        completed_at = datetime.now(UTC)
        detector_ver = executions[0].detector_version if executions else "0.2.0-heuristic-intel"
        policy_ver = executions[0].policy_version if executions else "2026.10.1"

        summary = ExperimentRunSummary(
            experiment_id=exp_id,
            experiment_name=config.experiment_name,
            goal=goal,
            status="completed",
            seed=config.seed,
            scenario_count=len(validated_scenarios),
            executed_count=len(executions),
            discrepancy_count=discrepancy_count,
            metrics=metrics,
            family_breakdown=metrics.get("family_breakdown", {}),
            detector_version=detector_ver,
            policy_version=policy_ver,
            started_at=started_at,
            completed_at=completed_at,
            findings=findings,
        )

        # Step 8: Handoff Package Construction
        handoff_pkg = EvaluationHandoff.create_package(
            summary=summary,
            scenarios=validated_scenarios,
            findings=findings,
        )

        # Persist results
        await self.recorder.persist_executions_and_findings(
            experiment_id=exp_id,
            executions=executions,
            findings=findings,
            summary=summary,
        )

        logger.info(
            f"Red AI experiment {exp_id} completed: {len(executions)} executed, "
            f"{discrepancy_count} discrepancies, {len(findings)} findings."
        )

        return summary, handoff_pkg, executions
