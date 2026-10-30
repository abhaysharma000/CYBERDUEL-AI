"""Independent Evaluation Engine REST API endpoints for candidate defense benchmarking."""

from __future__ import annotations

import logging
from typing import Annotated, Any
from uuid import UUID

from cyberduel_contracts.enums import (
    DefenseStatus,
    EvaluationStatus,
    EvaluationVerdict,
)
from cyberduel_contracts.evaluation import (
    AcceptancePolicyConfig,
    BenchmarkManifest,
    EvaluationReport,
    EvaluationRequest,
)
from cyberduel_contracts.policy import CandidateDefense
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.db.session import get_db_session
from apps.api.app.models.evaluations import (
    BenchmarkManifestRecord,
    EvaluationReportRecord,
    EvaluationRequestRecord,
)
from apps.api.app.models.policies import (
    CandidateDefenseRecord,
)
from services.evaluator.app.benchmarks import BenchmarkRegistry
from services.evaluator.app.runner import EvaluationRunner

logger = logging.getLogger("api.evaluations")
router = APIRouter(prefix="/evaluations", tags=["Independent Evaluation Engine"])

_benchmark_registry = BenchmarkRegistry()
_evaluation_runner = EvaluationRunner(benchmark_registry=_benchmark_registry)


class CreateEvaluationRequest(BaseModel):
    """Payload to trigger an independent benchmark evaluation for a candidate defense."""

    candidate_id: UUID = Field(..., description="ID of the CandidateDefense to evaluate")
    benchmark_manifest_version: str = Field(
        default="benchmark-golden-v1",
        description="Version or ID of the benchmark manifest to execute against",
    )
    acceptance_policy: AcceptancePolicyConfig = Field(
        default_factory=AcceptancePolicyConfig,
        description="Configurable acceptance gates for the evaluation",
    )
    requested_by: str = Field(
        default="API-Caller",
        description="Identity of requesting entity or agent",
    )


class EvaluationSummaryResponse(BaseModel):
    """High-level summary of an evaluation request."""

    id: UUID | None = None
    request_id: UUID
    candidate_id: UUID
    candidate_version: str
    baseline_version: str | None = None
    status: str
    benchmark_manifest_id: str
    verdict: str | None = None
    verdict_rationale: str | None = None
    evaluated_at: str | None = None
    candidate_metrics: dict[str, Any] | None = None
    created_at: str


@router.post("", response_model=EvaluationReport, status_code=status.HTTP_201_CREATED)
async def submit_evaluation(
    payload: CreateEvaluationRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> EvaluationReport:
    """Submit a candidate defense to the Independent Evaluation Engine for benchmark auditing."""
    # Look up candidate defense
    stmt = select(CandidateDefenseRecord).where(CandidateDefenseRecord.id == payload.candidate_id)
    result = await session.execute(stmt)
    candidate_rec = result.scalar_one_or_none()
    if not candidate_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Candidate defense {payload.candidate_id} not found",
        )

    contract_candidate = CandidateDefense(
        defense_id=candidate_rec.id,
        version=candidate_rec.version,
        author_agent=candidate_rec.author_agent,
        description=candidate_rec.description,
        rule_spec=candidate_rec.rule_spec,
        status=DefenseStatus.EVALUATING,
    )

    manifest_id = payload.benchmark_manifest_version
    bench_manifest = _benchmark_registry.get_manifest(manifest_id)
    if not bench_manifest:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Benchmark manifest '{manifest_id}' not found in registry",
        )

    # Ensure manifest in DB
    m_stmt = select(BenchmarkManifestRecord).where(BenchmarkManifestRecord.id == manifest_id)
    m_res = await session.execute(m_stmt)
    if not m_res.scalar_one_or_none():
        manifest_rec = BenchmarkManifestRecord(
            id=bench_manifest.manifest_id,
            name=bench_manifest.name,
            version=bench_manifest.version,
            description=bench_manifest.description,
            split_counts=bench_manifest.split_counts,
            family_counts=bench_manifest.family_counts,
            scenario_count=bench_manifest.scenario_count,
            scenarios_payload=[s.model_dump(mode="json") for s in bench_manifest.scenarios],
            integrity_hash=bench_manifest.integrity_hash,
        )
        session.add(manifest_rec)
        await session.flush()

    eval_req = EvaluationRequest(
        candidate_id=candidate_rec.id,
        candidate_version=candidate_rec.version,
        benchmark_manifest_version=manifest_id,
        acceptance_policy=payload.acceptance_policy,
        requested_by=payload.requested_by,
        status=EvaluationStatus.RUNNING,
    )

    eval_req_rec = EvaluationRequestRecord(
        id=eval_req.request_id,
        candidate_id=candidate_rec.id,
        candidate_version=candidate_rec.version,
        baseline_detector_version="0.2.0-heuristic-intel",
        baseline_policy_version="2026.10.1",
        benchmark_manifest_id=manifest_id,
        status="running",
        requested_by=payload.requested_by,
        resource_budget={"budget_seconds": 60.0},
        target_finding_ids=[],
        target_scenario_ids=[],
    )
    session.add(eval_req_rec)
    await session.flush()

    # Run independent evaluation without exposing ground-truth labels
    report = await _evaluation_runner.run_evaluation(
        request=eval_req,
        candidate=contract_candidate,
        manifest=bench_manifest,
    )

    eval_req_rec.status = report.status.value

    # Persist report
    report_rec = EvaluationReportRecord(
        id=report.report_id,
        request_id=eval_req.request_id,
        candidate_id=candidate_rec.id,
        candidate_version=report.candidate_version,
        baseline_version=report.baseline_version,
        benchmark_manifest_id=report.benchmark_manifest_version,
        verdict=report.verdict.value,
        status=report.status.value,
        verdict_rationale=report.verdict_rationale,
        acceptance_reasons=report.acceptance_reasons,
        rejection_reasons=report.rejection_reasons,
        baseline_metrics=report.baseline_metrics.model_dump(),
        candidate_metrics=report.candidate_metrics.model_dump(),
        split_metrics={k: v.model_dump() for k, v in report.split_metrics.items()},
        improvement_metrics=report.improvement_metrics.model_dump(),
        operational_metrics=report.operational_metrics.model_dump(),
        report_digest=report.report_digest,
        evaluated_at=report.evaluated_at,
    )
    session.add(report_rec)

    # If accepted, mark candidate approved (eligible for release)
    if report.verdict == EvaluationVerdict.PASS:
        candidate_rec.status = DefenseStatus.APPROVED.value
    else:
        candidate_rec.status = DefenseStatus.REJECTED.value

    await session.commit()
    return report


@router.get("", response_model=list[EvaluationSummaryResponse])
async def list_evaluations(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[EvaluationSummaryResponse]:
    """List historical evaluation requests with their status and verdicts."""
    stmt = (
        select(EvaluationRequestRecord)
        .order_by(EvaluationRequestRecord.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await session.execute(stmt)
    records = result.scalars().all()

    summaries: list[EvaluationSummaryResponse] = []
    for r in records:
        rep_stmt = select(EvaluationReportRecord).where(EvaluationReportRecord.request_id == r.id)
        rep_res = await session.execute(rep_stmt)
        rep = rep_res.scalar_one_or_none()

        summaries.append(
            EvaluationSummaryResponse(
                id=rep.id if rep else r.id,
                request_id=r.id,
                candidate_id=r.candidate_id,
                candidate_version=r.candidate_version,
                baseline_version=rep.baseline_version if rep else r.baseline_policy_version,
                status=r.status,
                benchmark_manifest_id=r.benchmark_manifest_id,
                verdict=rep.verdict if rep else None,
                verdict_rationale=rep.verdict_rationale if rep else None,
                evaluated_at=rep.evaluated_at.isoformat()
                if rep and rep.evaluated_at
                else r.created_at.isoformat(),
                candidate_metrics=rep.candidate_metrics if rep else None,
                created_at=r.created_at.isoformat(),
            )
        )
    return summaries


@router.get("/benchmarks", response_model=list[BenchmarkManifest])
async def list_benchmarks() -> list[BenchmarkManifest]:
    """List registered benchmark manifests available for evaluation."""
    return _benchmark_registry.list_manifests()


@router.get("/benchmarks/{manifest_id}", response_model=BenchmarkManifest)
async def get_benchmark(manifest_id: str) -> BenchmarkManifest:
    """Retrieve details and scenario distributions of a specific benchmark manifest."""
    m = _benchmark_registry.get_manifest(manifest_id)
    if not m:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Benchmark manifest '{manifest_id}' not found",
        )
    return m


@router.get("/{request_id}", response_model=EvaluationSummaryResponse)
async def get_evaluation(
    request_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> EvaluationSummaryResponse:
    """Retrieve summary status for a specific evaluation request."""
    stmt = select(EvaluationRequestRecord).where(EvaluationRequestRecord.id == request_id)
    res = await session.execute(stmt)
    record = res.scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evaluation request {request_id} not found",
        )

    rep_stmt = select(EvaluationReportRecord).where(EvaluationReportRecord.request_id == record.id)
    rep_res = await session.execute(rep_stmt)
    rep = rep_res.scalar_one_or_none()

    return EvaluationSummaryResponse(
        request_id=record.id,
        candidate_id=record.candidate_id,
        candidate_version=record.candidate_version,
        status=record.status,
        benchmark_manifest_id=record.benchmark_manifest_id,
        verdict=rep.verdict if rep else None,
        verdict_rationale=rep.verdict_rationale if rep else None,
        created_at=record.created_at.isoformat(),
    )


@router.get("/{request_id}/report", response_model=EvaluationReport)
async def get_evaluation_report(
    request_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> EvaluationReport:
    """Retrieve the full detailed EvaluationReport for an audit request."""
    stmt = select(EvaluationReportRecord).where(
        or_(
            EvaluationReportRecord.request_id == request_id,
            EvaluationReportRecord.id == request_id,
        )
    )
    res = await session.execute(stmt)
    rep = res.scalar_one_or_none()
    if not rep:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evaluation report for request {request_id} not found",
        )

    from cyberduel_contracts.evaluation import (
        ConfusionMatrix,
        ImprovementMetrics,
        OperationalMetrics,
    )

    return EvaluationReport(
        report_id=rep.id,
        request_id=rep.request_id,
        candidate_id=rep.candidate_id,
        candidate_version=rep.candidate_version,
        baseline_version=rep.baseline_version,
        benchmark_manifest_version=rep.benchmark_manifest_id,
        verdict=EvaluationVerdict(rep.verdict),
        status=EvaluationStatus(rep.status),
        verdict_rationale=rep.verdict_rationale,
        acceptance_reasons=rep.acceptance_reasons,
        rejection_reasons=rep.rejection_reasons,
        baseline_metrics=ConfusionMatrix.model_validate(rep.baseline_metrics),
        candidate_metrics=ConfusionMatrix.model_validate(rep.candidate_metrics),
        split_metrics={k: ConfusionMatrix.model_validate(v) for k, v in rep.split_metrics.items()},
        improvement_metrics=ImprovementMetrics.model_validate(rep.improvement_metrics),
        operational_metrics=OperationalMetrics.model_validate(rep.operational_metrics),
        report_digest=rep.report_digest,
        evaluated_at=rep.evaluated_at,
    )


@router.get("/{request_id}/metrics")
async def get_evaluation_metrics(
    request_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> dict[str, Any]:
    """Retrieve confusion matrices, split breakdowns, and operational metrics."""
    stmt = select(EvaluationReportRecord).where(
        or_(
            EvaluationReportRecord.request_id == request_id,
            EvaluationReportRecord.id == request_id,
        )
    )
    res = await session.execute(stmt)
    rep = res.scalar_one_or_none()
    if not rep:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evaluation report for request {request_id} not found",
        )

    return {
        "report_id": str(rep.id),
        "request_id": str(rep.request_id),
        "candidate_version": rep.candidate_version,
        "verdict": rep.verdict,
        "baseline_metrics": rep.baseline_metrics,
        "candidate_metrics": rep.candidate_metrics,
        "split_metrics": rep.split_metrics,
        "improvement_metrics": rep.improvement_metrics,
        "operational_metrics": rep.operational_metrics,
    }
