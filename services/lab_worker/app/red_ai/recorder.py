"""Experiment Recorder for transactional database persistence of laboratory experiments."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from cyberduel_contracts.lab import (
    ExperimentConfig,
    ExperimentRunSummary,
    FailureFinding,
    ScenarioContract,
    ScenarioExecutionResult,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.lab import (
    FailureFindingRecord,
    LabExperimentRecord,
    ScenarioExecutionRecord,
    ScenarioRecord,
)

logger = logging.getLogger("experiment_recorder")


def _safe_json(val: Any) -> Any:
    if val is None:
        return None
    return json.loads(json.dumps(val, default=str))


class ExperimentRecorder:
    """Manages transactional persistence and retrieval of research laboratory experiments."""

    def __init__(self, session: AsyncSession | None = None) -> None:
        self.session = session

    async def create_experiment(
        self,
        experiment_id: UUID,
        config: ExperimentConfig,
        scenario_count: int,
    ) -> LabExperimentRecord | None:
        """Create initial experiment record in 'created' status."""
        if self.session is None:
            return None

        exp_record = LabExperimentRecord(
            id=experiment_id,
            name=config.experiment_name,
            goal=config.goal,
            status="created",
            seed=config.seed,
            scenario_count=scenario_count,
            completed_count=0,
            discrepancy_count=0,
            configuration=config.model_dump(),
            summary_metrics={},
            detector_version="0.2.0-heuristic-intel",
            policy_version="2026.10.1",
            started_at=datetime.now(UTC),
        )
        self.session.add(exp_record)
        await self.session.flush()
        return exp_record

    async def persist_scenarios(
        self,
        experiment_id: UUID,
        scenarios: list[ScenarioContract],
    ) -> None:
        """Persist scenario definitions linked to this experiment."""
        if self.session is None:
            return

        for sc in scenarios:
            rec = ScenarioRecord(
                id=sc.scenario_id,
                experiment_id=experiment_id,
                scenario_family=sc.scenario_family,
                scenario_name=sc.scenario_name,
                description=sc.description,
                expected_class=sc.expected_class,
                expected_decision=sc.expected_decision.value,
                difficulty=sc.difficulty,
                tags=sc.tags,
                seed=sc.seed,
                generator_version=sc.generator_version,
                mutation_parent_id=sc.mutation_parent_id,
                transformation_history=_safe_json(sc.transformation_history),
                input_fixture=_safe_json(sc.input_fixture),
                expected_evidence=_safe_json(sc.expected_evidence),
                provenance=_safe_json(sc.provenance),
                safety_classification=sc.safety_classification,
            )
            self.session.add(rec)
        await self.session.flush()

    async def persist_executions_and_findings(
        self,
        experiment_id: UUID,
        executions: list[ScenarioExecutionResult],
        findings: list[FailureFinding],
        summary: ExperimentRunSummary,
    ) -> None:
        """Persist all execution observations, findings, and update overall experiment status."""
        if self.session is None:
            return

        # 1. Add executions
        for ex in executions:
            exec_rec = ScenarioExecutionRecord(
                id=ex.execution_id,
                experiment_id=experiment_id,
                scenario_id=ex.scenario_id,
                raw_url=ex.raw_url,
                expected_class=ex.expected_class,
                expected_decision=ex.expected_decision.value,
                actual_decision=ex.actual_decision.value,
                actual_threat_score=ex.actual_threat_score,
                actual_evidence=ex.actual_evidence,
                detector_version=ex.detector_version,
                policy_version=ex.policy_version,
                is_discrepancy=ex.is_discrepancy,
                discrepancy_type=ex.discrepancy_type,
                duration_ms=ex.duration_ms,
            )
            self.session.add(exec_rec)

        # 2. Add findings
        for f in findings:
            finding_rec = FailureFindingRecord(
                id=f.finding_id,
                experiment_id=experiment_id,
                failure_category=f.failure_category,
                discrepancy_type=f.discrepancy_type,
                hypothesis=f.hypothesis,
                affected_scenarios_count=f.affected_scenarios_count,
                representative_scenario_ids=[str(s) for s in f.representative_scenario_ids],
                suggested_remedy=f.suggested_remedy,
                severity=f.severity,
                status="open",
            )
            self.session.add(finding_rec)

        # 3. Update experiment record
        stmt = select(LabExperimentRecord).where(LabExperimentRecord.id == experiment_id)
        exp = (await self.session.execute(stmt)).scalars().first()
        if exp:
            exp.status = summary.status
            exp.completed_count = summary.executed_count
            exp.discrepancy_count = summary.discrepancy_count
            exp.summary_metrics = summary.metrics
            exp.detector_version = summary.detector_version
            exp.policy_version = summary.policy_version
            exp.completed_at = datetime.now(UTC)

        await self.session.commit()

    async def get_experiment(self, experiment_id: UUID) -> LabExperimentRecord | None:
        """Fetch experiment by UUID."""
        if self.session is None:
            return None
        stmt = select(LabExperimentRecord).where(LabExperimentRecord.id == experiment_id)
        return (await self.session.execute(stmt)).scalars().first()
