"""Blue AI Defense Engine API endpoints for research, candidate generation, and evaluation."""

from __future__ import annotations

import logging
from typing import Annotated, Any
from uuid import UUID

from cyberduel_contracts.enums import (
    Decision,
    DefenseStatus,
    ThreatSeverity,
)
from cyberduel_contracts.evaluation import EvaluationResult
from cyberduel_contracts.lab import (
    EvaluationHandoffPackage,
    FailureFinding,
    ScenarioContract,
)
from cyberduel_contracts.policy import (
    BaselineComparisonReport,
    BlueStatusResponse,
    CandidateDefense,
    CandidateFeedback,
    DefenseProposal,
    DefensiveHypothesis,
)
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.config import Settings, get_settings
from apps.api.app.core.rate_limit import rate_limit_dependency
from apps.api.app.db.session import get_db_session
from apps.api.app.models.lab import FailureFindingRecord, ScenarioRecord
from apps.api.app.models.policies import (
    CandidateDefenseRecord,
    DefenseHypothesisRecord,
    ResearchTaskRecord,
    SandboxComparisonRecord,
)
from apps.api.app.services.blue_ai import (
    CandidateDefenseBuilder,
    CandidateSandboxRunner,
    DefenseEvidenceService,
    DefenseHypothesisEngine,
    DefenseProposalGenerator,
    DefensiveResearchService,
    EvaluationHandoffService,
    LearningFeedbackService,
)
from apps.api.app.services.blue_ai.prioritizer import FailureCluster, PrioritizedFailureGroup

logger = logging.getLogger("blue_ai.api")

router = APIRouter(
    prefix="/blue", tags=["Blue AI Defense Engine"], dependencies=[Depends(rate_limit_dependency)]
)


def verify_blue_access(
    x_admin_key: Annotated[str | None, Header()] = None,
    settings: Settings = Depends(get_settings),
) -> None:
    """Ensure privileged Blue AI operations are authorized in production."""
    if settings.is_production and (not x_admin_key or x_admin_key != settings.SECRET_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: valid X-Admin-Key required for Blue AI operations.",
        )


class ResearchInitiateRequest(BaseModel):
    """Payload to initiate a Blue AI defensive research investigation."""

    handoff_package: EvaluationHandoffPackage | None = None
    experiment_id: UUID | None = None


class CandidateCreateRequest(BaseModel):
    """Request payload to synthesize a candidate defense package."""

    task_id: UUID
    failure_category: str | None = None
    proposal_type: str = Field(
        default="declarative_rule", pattern="^(declarative_rule|threshold_tuning)$"
    )
    auto_sandbox: bool = True


class CandidateEvaluateRequest(BaseModel):
    """Request payload to submit candidate defense to independent benchmark evaluation."""

    suite_id: str = "curated-golden-v1"


class CandidateBuildResponse(BaseModel):
    """Response returned upon synthesizing and sandboxing a candidate defense."""

    candidate: CandidateDefense
    hypothesis: DefensiveHypothesis
    proposal: DefenseProposal
    comparison: BaselineComparisonReport | None = None
    evidence_fingerprint: str | None = None


class CandidateEvaluateResponse(BaseModel):
    """Response returned upon independent evaluation of a candidate defense."""

    evaluation: EvaluationResult
    feedback: CandidateFeedback
    updated_candidate_status: str


@router.get("/status", response_model=BlueStatusResponse)
async def get_blue_status(
    session: AsyncSession = Depends(get_db_session),
) -> BlueStatusResponse:
    """Discover operational status and capabilities of the Blue AI Defense Engine."""
    # Active research tasks count
    task_count_stmt = select(func.count(ResearchTaskRecord.id)).where(
        ResearchTaskRecord.status == "active"
    )
    task_count_res = await session.execute(task_count_stmt)
    active_tasks = task_count_res.scalar() or 0

    # Total candidates built
    cand_stmt = select(func.count(CandidateDefenseRecord.id))
    cand_res = await session.execute(cand_stmt)
    total_candidates = cand_res.scalar() or 0

    # Approved candidates
    app_stmt = select(func.count(CandidateDefenseRecord.id)).where(
        CandidateDefenseRecord.status == "approved"
    )
    app_res = await session.execute(app_stmt)
    approved_candidates = app_res.scalar() or 0

    # Rejected candidates
    rej_stmt = select(func.count(CandidateDefenseRecord.id)).where(
        CandidateDefenseRecord.status == "rejected"
    )
    rej_res = await session.execute(rej_stmt)
    rejected_candidates = rej_res.scalar() or 0

    acceptance_rate = (
        round(approved_candidates / total_candidates, 4) if total_candidates > 0 else 0.0
    )

    return BlueStatusResponse(
        status="ready",
        active_research_tasks=active_tasks,
        total_candidates_built=total_candidates,
        accepted_candidates=approved_candidates,
        rejected_candidates=rejected_candidates,
        candidate_acceptance_rate=acceptance_rate,
        available_proposal_types=["declarative_rule", "threshold_tuning"],
    )


@router.post("/research", status_code=status.HTTP_201_CREATED)
async def initiate_research(
    payload: ResearchInitiateRequest,
    session: AsyncSession = Depends(get_db_session),
    _auth: None = Depends(verify_blue_access),
) -> dict[str, Any]:
    """Ingest Red AI handoff or load experiment findings to start a research investigation."""
    if payload.handoff_package:
        task_record, ranked_groups = await DefensiveResearchService.ingest_handoff(
            handoff=payload.handoff_package,
            session=session,
        )
    elif payload.experiment_id:
        # Load findings and scenarios from database
        findings_stmt = select(FailureFindingRecord).where(
            FailureFindingRecord.experiment_id == payload.experiment_id
        )
        f_res = await session.execute(findings_stmt)
        finding_records = f_res.scalars().all()

        scenarios_stmt = select(ScenarioRecord).where(
            ScenarioRecord.experiment_id == payload.experiment_id
        )
        s_res = await session.execute(scenarios_stmt)
        scenario_records = s_res.scalars().all()

        if not finding_records and not scenario_records:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No findings or scenarios found for experiment {payload.experiment_id}",
            )

        # Convert records to contracts
        scenarios: list[ScenarioContract] = [
            ScenarioContract(
                scenario_id=sr.id,
                scenario_family=sr.scenario_family,
                scenario_name=sr.scenario_name,
                description=sr.description,
                expected_class=sr.expected_class,
                expected_decision=Decision(sr.expected_decision),
                difficulty=sr.difficulty,  # type: ignore[arg-type]
                tags=sr.tags or [],
                seed=sr.seed,
                generator_version=sr.generator_version,
                input_fixture=sr.input_fixture or {},
                expected_evidence=sr.expected_evidence or [],
                provenance=sr.provenance or {},
                safety_classification="harmless_synthetic",
            )
            for sr in scenario_records
        ]

        findings: list[FailureFinding] = [
            FailureFinding(
                finding_id=fr.id,
                experiment_id=fr.experiment_id,
                failure_category=fr.failure_category,
                discrepancy_type=fr.discrepancy_type,
                hypothesis=fr.hypothesis,
                affected_scenarios_count=fr.affected_scenarios_count,
                representative_scenario_ids=[UUID(sid) for sid in fr.representative_scenario_ids],
                suggested_remedy=fr.suggested_remedy,
                severity=fr.severity,  # type: ignore[arg-type]
            )
            for fr in finding_records
        ]

        handoff = EvaluationHandoffPackage(
            experiment_id=payload.experiment_id,
            detector_version="1.0.0",
            policy_version="1.0.0",
            total_failures=len(findings),
            findings=findings,
            representative_scenarios=scenarios,
        )
        task_record, ranked_groups = await DefensiveResearchService.ingest_handoff(
            handoff=handoff,
            session=session,
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Must provide either handoff_package or experiment_id.",
        )

    return {
        "task_id": str(task_record.id),
        "name": task_record.name,
        "status": task_record.status,
        "findings_count": task_record.findings_count,
        "summary": task_record.summary,
        "top_priority": ranked_groups[0].recommended_focus if ranked_groups else None,
    }


@router.get("/research/{task_id}")
async def get_research_task(
    task_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Retrieve details, failure clusters, and hypotheses for a research task."""
    task = await DefensiveResearchService.get_task(task_id, session)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Research task {task_id} not found.",
        )

    # Fetch hypotheses for this task
    h_stmt = select(DefenseHypothesisRecord).where(
        DefenseHypothesisRecord.research_task_id == task_id
    )
    h_res = await session.execute(h_stmt)
    hypotheses = h_res.scalars().all()

    return {
        "task_id": str(task.id),
        "name": task.name,
        "status": task.status,
        "findings_count": task.findings_count,
        "summary": task.summary,
        "hypotheses_count": len(hypotheses),
        "hypotheses": [
            {
                "id": str(h.id),
                "failure_category": h.failure_category,
                "target_family": h.target_family,
                "hypothesis_text": h.hypothesis_text,
                "status": h.status,
                "confidence": h.confidence,
                "created_at": h.created_at.isoformat(),
            }
            for h in hypotheses
        ],
        "created_at": task.created_at.isoformat(),
    }


@router.get("/failure-groups")
async def list_failure_groups(
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(default=10, ge=1, le=50),
) -> list[dict[str, Any]]:
    """Retrieve recent failure findings grouped and prioritized for defensive action."""
    tasks = await DefensiveResearchService.list_tasks(session, limit=limit)
    aggregated_groups: list[dict[str, Any]] = []

    for task in tasks:
        summary = task.summary or {}
        groups = summary.get("ranked_groups", [])
        for g in groups:
            aggregated_groups.append({**g, "task_id": str(task.id)})

    return aggregated_groups[:limit]


@router.post(
    "/candidates", response_model=CandidateBuildResponse, status_code=status.HTTP_201_CREATED
)
async def create_candidate(
    payload: CandidateCreateRequest,
    session: AsyncSession = Depends(get_db_session),
    _auth: None = Depends(verify_blue_access),
) -> CandidateBuildResponse:
    """Formulate hypothesis, synthesize declarative rules, and package a candidate defense."""
    task = await DefensiveResearchService.get_task(payload.task_id, session)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Research task {payload.task_id} not found.",
        )

    # Extract failure cluster from task summary
    summary = task.summary or {}
    ranked = summary.get("ranked_groups", [])
    if not ranked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Research task contains no ranked failure groups.",
        )

    target_group_data = ranked[0]
    if payload.failure_category:
        for g in ranked:
            if g.get("failure_category") == payload.failure_category:
                target_group_data = g
                break

    cluster = FailureCluster(
        cluster_id=target_group_data.get("cluster_id", "cluster-1"),
        failure_category=target_group_data.get("failure_category", "general_threat"),
        target_family=target_group_data.get("target_family", "phishing_and_credential_theft"),
        discrepancy_type=target_group_data.get("discrepancy_type", "false_negative"),
        severity=ThreatSeverity(target_group_data.get("severity", "high")),
        findings=[],
        scenarios=[],
        affected_count=int(target_group_data.get("affected_count", 5)),
        sample_urls=target_group_data.get("sample_urls", []),
    )

    priority_group = PrioritizedFailureGroup(
        cluster=cluster,
        priority_score=float(target_group_data.get("priority_score", 0.85)),
        urgency_rank=int(target_group_data.get("urgency_rank", 1)),
        rationale=target_group_data.get("rationale", "Automated priority ranking"),
        recommended_focus=f"Target {cluster.failure_category}",
    )

    # 1. Formulate Hypothesis (via QwenProvider if configured, else procedural)
    hypothesis = await DefenseHypothesisEngine.formulate_hypothesis_async(
        task_id=task.id,
        priority_group=priority_group,
    )
    await DefenseHypothesisEngine.save_hypothesis(hypothesis, session)

    # 2. Synthesize Proposal
    proposal = await DefenseProposalGenerator.generate_proposal_async(hypothesis)
    await DefenseProposalGenerator.save_proposal(proposal, session)

    # 3. Assemble Candidate Defense
    count_stmt = select(func.count(CandidateDefenseRecord.id))
    c_res = await session.execute(count_stmt)
    seq = (c_res.scalar() or 0) + 1

    candidate = CandidateDefenseBuilder.assemble_candidate(
        proposals=[proposal],
        baseline_version="1.0.0",
        candidate_sequence=seq,
    )
    await CandidateDefenseBuilder.save_candidate(candidate, session)

    # 4. Optional Sandbox Comparative Evaluation
    comparison_report = None
    if payload.auto_sandbox:
        comparison_report = await CandidateSandboxRunner.run_comparison(
            candidate=candidate,
            failing_scenarios=None,
            extra_benign_urls=None,
            session=session,
        )

    # 5. Compile Evidence Dossier
    evidence_fingerprint = None
    if comparison_report:
        dossier = DefenseEvidenceService.compile_dossier(
            candidate=candidate,
            hypotheses=[hypothesis],
            proposals=[proposal],
            comparison=comparison_report,
            experiment_id=summary.get("experiment_id"),
        )
        evidence_fingerprint = dossier.get("dossier_fingerprint")

    return CandidateBuildResponse(
        candidate=candidate,
        hypothesis=hypothesis,
        proposal=proposal,
        comparison=comparison_report,
        evidence_fingerprint=evidence_fingerprint,
    )


@router.get("/candidates/{candidate_id}", response_model=CandidateDefense)
async def get_candidate(
    candidate_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> CandidateDefense:
    """Retrieve candidate defense metadata and compiled rule specifications."""
    rec = await CandidateDefenseBuilder.get_candidate(candidate_id, session)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Candidate defense {candidate_id} not found.",
        )

    return CandidateDefense(
        defense_id=rec.id,
        version=rec.version,
        author_agent=rec.author_agent,
        description=rec.description,
        rule_spec=rec.rule_spec or {},
        status=DefenseStatus(rec.status),
        created_at=rec.created_at,
    )


@router.get("/candidates/{candidate_id}/comparison", response_model=BaselineComparisonReport)
async def get_candidate_comparison(
    candidate_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> BaselineComparisonReport:
    """Retrieve side-by-side performance audit report for a candidate defense."""
    stmt = (
        select(SandboxComparisonRecord)
        .where(SandboxComparisonRecord.candidate_id == candidate_id)
        .order_by(SandboxComparisonRecord.created_at.desc())
    )
    res = await session.execute(stmt)
    rec = res.scalar_one_or_none()
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No sandbox comparison found for candidate {candidate_id}.",
        )

    return BaselineComparisonReport.model_validate(rec.report_payload)


@router.post(
    "/candidates/{candidate_id}/evaluate",
    response_model=CandidateEvaluateResponse,
)
async def evaluate_candidate(
    candidate_id: UUID,
    payload: CandidateEvaluateRequest = CandidateEvaluateRequest(),
    session: AsyncSession = Depends(get_db_session),
    _auth: None = Depends(verify_blue_access),
) -> CandidateEvaluateResponse:
    """Submit candidate defense to independent evaluator for benchmark audit."""
    rec = await CandidateDefenseBuilder.get_candidate(candidate_id, session)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Candidate defense {candidate_id} not found.",
        )

    candidate = CandidateDefense(
        defense_id=rec.id,
        version=rec.version,
        author_agent=rec.author_agent,
        description=rec.description,
        rule_spec=rec.rule_spec or {},
        status=DefenseStatus(rec.status),
        created_at=rec.created_at,
    )

    handoff_svc = EvaluationHandoffService()
    eval_result = await handoff_svc.submit_candidate(
        candidate=candidate,
        suite_id=payload.suite_id,
        session=session,
    )

    feedback = await LearningFeedbackService.record_feedback(
        candidate=candidate,
        evaluation_result=eval_result,
        session=session,
    )

    return CandidateEvaluateResponse(
        evaluation=eval_result,
        feedback=feedback,
        updated_candidate_status=candidate.status.value,
    )


@router.get("/history")
async def list_candidate_history(
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[dict[str, Any]]:
    """Retrieve historical audit trail of candidate defenses, verdicts, and regression metrics."""
    stmt = (
        select(CandidateDefenseRecord)
        .order_by(CandidateDefenseRecord.created_at.desc())
        .limit(limit)
    )
    res = await session.execute(stmt)
    records = res.scalars().all()

    return [
        {
            "id": str(r.id),
            "candidate_id": str(r.id),
            "candidate_version": r.version,
            "version": r.version,
            "defense_type": "rule_update",
            "author_agent": r.author_agent,
            "description": r.description,
            "changes_summary": r.description or "Automated defensive synthesis",
            "target_findings": [],
            "status": r.status,
            "rule_count": len((r.rule_spec or {}).get("rules", [])),
            "created_at": r.created_at.isoformat(),
            "updated_at": r.updated_at.isoformat() if hasattr(r, "updated_at") and r.updated_at else r.created_at.isoformat(),
        }
        for r in records
    ]
