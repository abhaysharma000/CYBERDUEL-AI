"""Research Laboratory API endpoints for synthetic scenario generation, adversarial experiments, and metrics."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from cyberduel_contracts.enums import Decision
from cyberduel_contracts.lab import (
    ExperimentConfig,
    ExperimentRunSummary,
    FailureFinding,
    LabMetricsResponse,
    LabStatusResponse,
    ScenarioContract,
    ScenarioExecutionResult,
    ScenarioGenerationRequest,
)
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.config import Settings, get_settings
from apps.api.app.core.rate_limit import rate_limit_dependency
from apps.api.app.db.session import get_db_session
from apps.api.app.models.lab import (
    FailureFindingRecord,
    LabExperimentRecord,
    ScenarioExecutionRecord,
    ScenarioRecord,
)
from services.lab_worker.app.config import worker_settings
from services.lab_worker.app.red_ai.agent import RedResearchAgent
from services.lab_worker.app.red_ai.generator import ScenarioGenerator
from services.lab_worker.app.red_ai.patterns import ThreatPatternLibrary
from services.lab_worker.app.red_ai.validator import ScenarioValidator

router = APIRouter(
    prefix="/lab", tags=["Research Laboratory"], dependencies=[Depends(rate_limit_dependency)]
)


def verify_lab_access(
    x_admin_key: Annotated[str | None, Header()] = None,
    settings: Settings = Depends(get_settings),
) -> None:
    """Ensure privileged laboratory execution operations are authorized in production."""
    if settings.is_production and (not x_admin_key or x_admin_key != settings.SECRET_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: valid X-Admin-Key required for research laboratory operations.",
        )


@router.get("/status", response_model=LabStatusResponse)
async def get_lab_status(
    session: AsyncSession = Depends(get_db_session),
) -> LabStatusResponse:
    """Discover operational status and capabilities of the Red AI Research Laboratory."""
    # Count active and completed experiments
    stmt_active = (
        select(func.count())
        .select_from(LabExperimentRecord)
        .where(LabExperimentRecord.status.in_(["created", "queued", "running"]))
    )
    active_count = (await session.execute(stmt_active)).scalar() or 0

    stmt_completed = (
        select(func.count())
        .select_from(LabExperimentRecord)
        .where(LabExperimentRecord.status == "completed")
    )
    completed_count = (await session.execute(stmt_completed)).scalar() or 0

    stmt_scenarios = select(func.count()).select_from(ScenarioRecord)
    scenarios_count = (await session.execute(stmt_scenarios)).scalar() or len(
        ThreatPatternLibrary.list_templates()
    )

    return LabStatusResponse(
        status="healthy",
        active_experiments=active_count,
        completed_experiments=completed_count,
        total_scenarios_cataloged=scenarios_count,
        sandboxed=worker_settings.SANDBOX_STRICT,
        external_network_blocked=not worker_settings.ALLOW_EXTERNAL_NETWORK,
        worker_version=worker_settings.WORKER_VERSION,
        supported_families=ThreatPatternLibrary.supported_families(),
    )


@router.post(
    "/scenarios/generate",
    response_model=list[ScenarioContract],
    dependencies=[Depends(verify_lab_access)],
)
async def generate_scenarios(
    request: ScenarioGenerationRequest,
) -> list[ScenarioContract]:
    """Generate a deterministic batch of validated synthetic scenarios without running an experiment."""
    generator = ScenarioGenerator(seed=request.seed)
    raw_scenarios = await generator.generate_corpus_async(
        count=request.count,
        families=request.families,
        mutation_depth=request.mutation_depth,
        goal=request.goal,
    )

    validated: list[ScenarioContract] = []
    for s in raw_scenarios:
        v = ScenarioValidator.validate(s)
        if v.is_valid:
            validated.append(s)

    return validated


@router.post(
    "/experiments",
    response_model=ExperimentRunSummary,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(verify_lab_access)],
)
async def run_experiment(
    config: ExperimentConfig,
    session: AsyncSession = Depends(get_db_session),
) -> ExperimentRunSummary:
    """Execute complete 8-step adversarial laboratory experiment against the defensive engine."""
    agent = RedResearchAgent(session=session)
    summary, handoff, executions = await agent.run_experiment(config)
    return summary


@router.get("/experiments", response_model=list[ExperimentRunSummary])
async def list_experiments(
    session: AsyncSession = Depends(get_db_session),
    status: str | None = None,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[ExperimentRunSummary]:
    """List lab experiments with pagination and status filter."""
    stmt = select(LabExperimentRecord)
    if status:
        stmt = stmt.where(LabExperimentRecord.status == status)
    stmt = stmt.order_by(LabExperimentRecord.created_at.desc()).offset(offset).limit(limit)
    experiments = (await session.execute(stmt)).scalars().all()

    summaries = []
    for exp in experiments:
        stmt_findings = select(FailureFindingRecord).where(
            FailureFindingRecord.experiment_id == exp.id
        )
        finding_recs = (await session.execute(stmt_findings)).scalars().all()
        findings = [
            FailureFinding(
                finding_id=f.id,
                experiment_id=f.experiment_id,
                failure_category=f.failure_category,
                discrepancy_type=f.discrepancy_type,
                hypothesis=f.hypothesis,
                affected_scenarios_count=f.affected_scenarios_count,
                representative_scenario_ids=[UUID(sid) for sid in f.representative_scenario_ids],
                suggested_remedy=f.suggested_remedy,
                severity=f.severity,  # type: ignore[arg-type]
            )
            for f in finding_recs
        ]
        summaries.append(
            ExperimentRunSummary(
                experiment_id=exp.id,
                experiment_name=exp.name,
                goal=exp.goal,
                status=exp.status,
                seed=exp.seed,
                scenario_count=exp.scenario_count,
                executed_count=exp.completed_count,
                discrepancy_count=exp.discrepancy_count,
                metrics=exp.summary_metrics or {},
                family_breakdown=(exp.summary_metrics or {}).get("family_breakdown", {}),
                detector_version=exp.detector_version,
                policy_version=exp.policy_version,
                started_at=exp.started_at,
                completed_at=exp.completed_at,
                findings=findings,
            )
        )
    return summaries


@router.get("/experiments/{experiment_id}", response_model=ExperimentRunSummary)
async def get_experiment(
    experiment_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> ExperimentRunSummary:
    """Retrieve experiment run summary, metrics, and findings by UUID."""
    stmt = select(LabExperimentRecord).where(LabExperimentRecord.id == experiment_id)
    exp = (await session.execute(stmt)).scalars().first()
    if not exp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Experiment '{experiment_id}' not found.",
        )

    # Fetch findings
    stmt_findings = select(FailureFindingRecord).where(
        FailureFindingRecord.experiment_id == experiment_id
    )
    finding_recs = (await session.execute(stmt_findings)).scalars().all()
    findings = [
        FailureFinding(
            finding_id=f.id,
            experiment_id=f.experiment_id,
            failure_category=f.failure_category,
            discrepancy_type=f.discrepancy_type,
            hypothesis=f.hypothesis,
            affected_scenarios_count=f.affected_scenarios_count,
            representative_scenario_ids=[UUID(sid) for sid in f.representative_scenario_ids],
            suggested_remedy=f.suggested_remedy,
            severity=f.severity,  # type: ignore[arg-type]
        )
        for f in finding_recs
    ]

    return ExperimentRunSummary(
        experiment_id=exp.id,
        experiment_name=exp.name,
        goal=exp.goal,
        status=exp.status,
        seed=exp.seed,
        scenario_count=exp.scenario_count,
        executed_count=exp.completed_count,
        discrepancy_count=exp.discrepancy_count,
        metrics=exp.summary_metrics,
        family_breakdown=exp.summary_metrics.get("family_breakdown", {}),
        detector_version=exp.detector_version,
        policy_version=exp.policy_version,
        started_at=exp.started_at,
        completed_at=exp.completed_at,
        findings=findings,
    )


@router.get("/experiments/{experiment_id}/results", response_model=list[ScenarioExecutionResult])
async def get_experiment_results(
    experiment_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[ScenarioExecutionResult]:
    """Retrieve individual scenario execution observations for an experiment."""
    stmt = (
        select(
            ScenarioExecutionRecord, ScenarioRecord.scenario_family, ScenarioRecord.scenario_name
        )
        .join(ScenarioRecord, ScenarioExecutionRecord.scenario_id == ScenarioRecord.id)
        .where(ScenarioExecutionRecord.experiment_id == experiment_id)
        .limit(limit)
    )
    rows = (await session.execute(stmt)).all()
    if not rows:
        # Check if experiment exists
        exp_stmt = select(LabExperimentRecord).where(LabExperimentRecord.id == experiment_id)
        exp = (await session.execute(exp_stmt)).scalars().first()
        if not exp:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Experiment '{experiment_id}' not found.",
            )
        return []

    results = []
    for exec_rec, fam, name in rows:
        results.append(
            ScenarioExecutionResult(
                execution_id=exec_rec.id,
                experiment_id=exec_rec.experiment_id,
                scenario_id=exec_rec.scenario_id,
                scenario_name=name,
                scenario_family=fam,
                raw_url=exec_rec.raw_url,
                expected_class=exec_rec.expected_class,
                expected_decision=Decision(exec_rec.expected_decision),
                actual_decision=Decision(exec_rec.actual_decision),
                actual_threat_score=exec_rec.actual_threat_score,
                actual_evidence=exec_rec.actual_evidence,
                detector_version=exec_rec.detector_version,
                policy_version=exec_rec.policy_version,
                is_discrepancy=exec_rec.is_discrepancy,
                discrepancy_type=exec_rec.discrepancy_type,
                duration_ms=exec_rec.duration_ms,
                executed_at=exec_rec.created_at,
            )
        )
    return results


@router.post("/experiments/{experiment_id}/cancel", dependencies=[Depends(verify_lab_access)])
async def cancel_experiment(
    experiment_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Cancel a queued or running experiment."""
    stmt = select(LabExperimentRecord).where(LabExperimentRecord.id == experiment_id)
    exp = (await session.execute(stmt)).scalars().first()
    if not exp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Experiment '{experiment_id}' not found.",
        )

    if exp.status in {"completed", "failed", "cancelled"}:
        return {
            "status": exp.status,
            "message": f"Experiment is already in terminal state '{exp.status}'.",
        }

    exp.status = "cancelled"
    await session.commit()
    return {"status": "cancelled", "experiment_id": str(experiment_id)}


@router.get("/scenarios", response_model=list[ScenarioContract])
async def list_scenarios(
    family: str | None = None,
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[ScenarioContract]:
    """List cataloged scenarios from the database or fall back to template library."""
    stmt = select(ScenarioRecord)
    if family:
        stmt = stmt.where(ScenarioRecord.scenario_family == family)
    stmt = stmt.limit(limit)

    db_scenarios = (await session.execute(stmt)).scalars().all()
    if db_scenarios:
        return [
            ScenarioContract(
                scenario_id=s.id,
                schema_version="1.0.0",
                scenario_family=s.scenario_family,
                scenario_name=s.scenario_name,
                description=s.description,
                expected_class=s.expected_class,
                expected_decision=Decision(s.expected_decision),
                difficulty=s.difficulty,  # type: ignore[arg-type]
                tags=s.tags,
                seed=s.seed,
                generator_version=s.generator_version,
                mutation_parent_id=s.mutation_parent_id,
                transformation_history=s.transformation_history,
                input_fixture=s.input_fixture,
                expected_evidence=s.expected_evidence,
                provenance=s.provenance,
                safety_classification=s.safety_classification,  # type: ignore[arg-type]
                created_at=s.created_at,
            )
            for s in db_scenarios
        ]

    # Fallback to generating from pattern library
    generator = ScenarioGenerator(seed=42)
    return generator.generate_corpus(count=limit, families=[family] if family else None)


@router.get("/scenarios/{scenario_id}", response_model=ScenarioContract)
async def get_scenario(
    scenario_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> ScenarioContract:
    """Retrieve detailed scenario definition by UUID."""
    stmt = select(ScenarioRecord).where(ScenarioRecord.id == scenario_id)
    s = (await session.execute(stmt)).scalars().first()
    if not s:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{scenario_id}' not found.",
        )

    return ScenarioContract(
        scenario_id=s.id,
        schema_version="1.0.0",
        scenario_family=s.scenario_family,
        scenario_name=s.scenario_name,
        description=s.description,
        expected_class=s.expected_class,
        expected_decision=Decision(s.expected_decision),
        difficulty=s.difficulty,  # type: ignore[arg-type]
        tags=s.tags,
        seed=s.seed,
        generator_version=s.generator_version,
        mutation_parent_id=s.mutation_parent_id,
        transformation_history=s.transformation_history,
        input_fixture=s.input_fixture,
        expected_evidence=s.expected_evidence,
        provenance=s.provenance,
        safety_classification=s.safety_classification,  # type: ignore[arg-type]
        created_at=s.created_at,
    )


@router.get("/metrics", response_model=LabMetricsResponse)
async def get_lab_metrics(
    session: AsyncSession = Depends(get_db_session),
) -> LabMetricsResponse:
    """Retrieve aggregate detection and discrepancy metrics across all completed experiments."""
    stmt_exp = select(LabExperimentRecord).where(LabExperimentRecord.status == "completed")
    exps = (await session.execute(stmt_exp)).scalars().all()

    total_scenarios_gen = sum(e.scenario_count for e in exps)
    total_scenarios_exec = sum(e.completed_count for e in exps)

    # Compute macro-averages across completed experiments
    accuracies = [
        e.summary_metrics.get("accuracy", 0.0) for e in exps if "accuracy" in e.summary_metrics
    ]
    tprs = [e.summary_metrics.get("recall", 0.0) for e in exps if "recall" in e.summary_metrics]
    fprs = [
        e.summary_metrics.get("false_positive_rate", 0.0)
        for e in exps
        if "false_positive_rate" in e.summary_metrics
    ]

    avg_acc = sum(accuracies) / len(accuracies) if accuracies else 1.0
    avg_tpr = sum(tprs) / len(tprs) if tprs else 1.0
    avg_fpr = sum(fprs) / len(fprs) if fprs else 0.0

    return LabMetricsResponse(
        total_scenarios_generated=total_scenarios_gen,
        total_scenarios_executed=total_scenarios_exec,
        total_experiments_run=len(exps),
        overall_accuracy=round(avg_acc, 4),
        overall_tpr=round(avg_tpr, 4),
        overall_fpr=round(avg_fpr, 4),
        decision_distribution={},
        discrepancy_distribution={},
        failure_category_distribution={},
    )
