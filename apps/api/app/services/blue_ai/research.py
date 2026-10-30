"""Defensive research ingestion service for Blue AI.

Ingests Red AI evaluation handoffs, extracts failure patterns,
clusters detection gaps, and initiates defensive research tasks.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID, uuid4

from cyberduel_contracts.lab import EvaluationHandoffPackage, FailureFinding, ScenarioContract
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.policies import ResearchTaskRecord
from apps.api.app.services.blue_ai.prioritizer import (
    DefensePrioritizationEngine,
    FailureCluster,
    PrioritizedFailureGroup,
)

logger = logging.getLogger("blue_ai.research")


class DefensiveResearchService:
    """Manages ingestion of adversarial findings and coordination of defensive investigations."""

    @classmethod
    def cluster_findings(
        cls,
        findings: list[FailureFinding],
        scenarios: list[ScenarioContract],
    ) -> list[FailureCluster]:
        """Group failure findings and scenarios by category and target family."""
        scenario_map: dict[UUID, ScenarioContract] = {s.scenario_id: s for s in scenarios}
        cluster_buckets: dict[str, FailureCluster] = {}

        for finding in findings:
            cat = finding.failure_category
            disc = finding.discrepancy_type
            key = f"{cat}::{disc}"

            if key not in cluster_buckets:
                # Determine family from representative scenarios
                sample_scenarios = [
                    scenario_map[sid]
                    for sid in finding.representative_scenario_ids
                    if sid in scenario_map
                ]
                target_fam = (
                    (
                        sample_scenarios[0].scenario_family.value
                        if hasattr(sample_scenarios[0].scenario_family, "value")
                        else str(sample_scenarios[0].scenario_family)
                    )
                    if sample_scenarios
                    else "general_threat"
                )
                sample_urls = [
                    (
                        s.input_fixture.get("raw_url", "")
                        if isinstance(s.input_fixture, dict)
                        else getattr(s.input_fixture, "raw_url", "")
                    )
                    for s in sample_scenarios
                    if s.input_fixture
                ]
                sample_urls = [u for u in sample_urls if u]

                cluster_buckets[key] = FailureCluster(
                    cluster_id=f"cluster-{len(cluster_buckets) + 1}",
                    failure_category=cat,
                    target_family=target_fam,
                    discrepancy_type=disc,
                    severity=finding.severity,
                    findings=[finding],
                    scenarios=sample_scenarios,
                    affected_count=finding.affected_scenarios_count,
                    sample_urls=sample_urls,
                )
            else:
                existing = cluster_buckets[key]
                existing.findings.append(finding)
                existing.affected_count += finding.affected_scenarios_count
                for sid in finding.representative_scenario_ids:
                    if sid in scenario_map and scenario_map[sid] not in existing.scenarios:
                        existing.scenarios.append(scenario_map[sid])
                        fix = scenario_map[sid].input_fixture
                        u = (
                            fix.get("raw_url", "")
                            if isinstance(fix, dict)
                            else getattr(fix, "raw_url", "")
                        )
                        if u:
                            existing.sample_urls.append(u)

        return list(cluster_buckets.values())

    @classmethod
    async def ingest_handoff(
        cls,
        handoff: EvaluationHandoffPackage,
        session: AsyncSession | None = None,
        rejected_categories: set[str] | None = None,
    ) -> tuple[ResearchTaskRecord, list[PrioritizedFailureGroup]]:
        """Ingest Red AI handoff package, prioritize clusters, and create a research task."""
        logger.info(
            f"Ingesting Red AI handoff {handoff.handoff_id} with {len(handoff.findings)} findings"
        )

        clusters = cls.cluster_findings(handoff.findings, handoff.representative_scenarios)
        ranked_groups = DefensePrioritizationEngine.rank_clusters(
            clusters, negative_feedback_categories=rejected_categories
        )

        task_id = uuid4()
        now = datetime.now(UTC)
        summary_payload = {
            "handoff_id": str(handoff.handoff_id),
            "experiment_id": str(handoff.experiment_id) if handoff.experiment_id else None,
            "detector_version": handoff.detector_version,
            "policy_version": handoff.policy_version,
            "total_failures": handoff.total_failures,
            "cluster_count": len(clusters),
            "top_priority": ranked_groups[0].recommended_focus if ranked_groups else "None",
            "ranked_groups": [
                {
                    "cluster_id": rg.cluster.cluster_id,
                    "failure_category": rg.cluster.failure_category,
                    "target_family": rg.cluster.target_family,
                    "discrepancy_type": rg.cluster.discrepancy_type,
                    "severity": rg.cluster.severity.value
                    if hasattr(rg.cluster.severity, "value")
                    else str(rg.cluster.severity),
                    "priority_score": rg.priority_score,
                    "urgency_rank": rg.urgency_rank,
                    "affected_count": rg.cluster.affected_count,
                    "sample_urls": rg.cluster.sample_urls[:5],
                    "rationale": rg.rationale,
                }
                for rg in ranked_groups
            ],
        }

        task_record = ResearchTaskRecord(
            id=task_id,
            name=f"ResearchTask-Exp-{str(handoff.experiment_id)[:8] if handoff.experiment_id else 'Direct'}",
            status="active",
            experiment_id=handoff.experiment_id,
            findings_count=len(handoff.findings),
            summary=summary_payload,
            started_at=now,
            created_at=now,
            updated_at=now,
        )

        if session is not None:
            session.add(task_record)
            await session.commit()
            await session.refresh(task_record)

        return task_record, ranked_groups

    @classmethod
    async def get_task(
        cls,
        task_id: UUID,
        session: AsyncSession,
    ) -> ResearchTaskRecord | None:
        """Fetch research task by primary key."""
        stmt = select(ResearchTaskRecord).where(ResearchTaskRecord.id == task_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def list_tasks(
        cls,
        session: AsyncSession,
        limit: int = 20,
    ) -> list[ResearchTaskRecord]:
        """List recent research tasks ordered descending by creation date."""
        stmt = (
            select(ResearchTaskRecord).order_by(ResearchTaskRecord.created_at.desc()).limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
