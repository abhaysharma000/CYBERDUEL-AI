"""Explainable URL analysis and retrieval endpoints."""

from uuid import UUID

from cyberduel_contracts.analysis import (
    EvidenceItem,
    URLAnalysisRequest,
    URLAnalysisResponse,
)
from cyberduel_contracts.enums import Decision, ProvenanceType
from cyberduel_threat_intel.validator import URLValidator
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.rate_limit import rate_limit_dependency
from apps.api.app.db.session import get_db_session
from apps.api.app.models.analysis import ThreatAnalysisRecord
from apps.api.app.services.url_analysis_service import URLAnalysisService

router = APIRouter(prefix="/analyze", tags=["URL Analysis"])


@router.post(
    "/url",
    response_model=URLAnalysisResponse,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Analyze URL for Threats and Anomalies",
    description=(
        "Executes defensive URL analysis including canonical normalization, local threat intelligence lookup, "
        "deterministic heuristics, and explainable risk scoring. Never crawls or executes arbitrary remote targets."
    ),
)
async def analyze_url_endpoint(
    request: URLAnalysisRequest,
    session: AsyncSession = Depends(get_db_session),
) -> URLAnalysisResponse:
    # 1. Structural validation
    val = URLValidator.validate(request.url)
    if not val.is_valid or not val.normalized:
        return URLAnalysisResponse(
            input_validation_status="malformed",
            safe_normalized_url=request.url[:256],
            normalized_identifier="invalid_hash",
            decision=Decision.ALLOW,
            threat_score=0.0,
            evidence=[
                EvidenceItem(
                    category="validation",
                    reason=f"URL rejected during structural validation: {val.error_message}",
                )
            ],
            matched_indicators=[],
            engine_version=URLAnalysisService.ENGINE_VERSION,
            policy_version=URLAnalysisService.POLICY_VERSION,
            confidence=None,
            provenance=ProvenanceType.LOCAL_RULE,
            explanation=f"Malformed input: {val.error_message}",
            fail_safe_applied=False,
        )

    service = URLAnalysisService(session=session)
    result = await service.analyze_url(
        raw_url=request.url,
        client_id=request.client_id,
        context=request.context,
    )

    norm = val.normalized
    matched_inds = [
        e.reason.split("'")[1]
        for e in result.evidence
        if e.category == "threat_intelligence" and "'" in e.reason
    ]

    # Generate explanatory summary text
    if result.decision == Decision.BLOCK:
        explanation = (
            f"Blocked: Critical threat indicators detected (Score: {result.threat_score:.2f})."
        )
    elif result.decision == Decision.WARN:
        explanation = f"Caution advised: Suspicious structural or lexical characteristics identified (Score: {result.threat_score:.2f})."
    else:
        explanation = "Safe: No threat intelligence or heuristic risk indicators detected."

    return URLAnalysisResponse(
        analysis_id=result.analysis_id,
        input_validation_status="valid",
        safe_normalized_url=norm.canonical_url,
        normalized_identifier=norm.url_sha256,
        decision=result.decision,
        threat_score=result.threat_score,
        evidence=result.evidence,
        matched_indicators=matched_inds,
        engine_version=result.engine_version,
        policy_version=result.policy_version,
        confidence=result.confidence,
        provenance=result.provenance,
        explanation=explanation,
        fail_safe_applied=False,
        analyzed_at=result.created_at,
    )


@router.get(
    "/{analysis_id}",
    response_model=URLAnalysisResponse,
    summary="Retrieve Prior Analysis Record",
    description="Fetches an existing threat analysis verdict by its unique UUID.",
)
async def get_analysis_record(
    analysis_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> URLAnalysisResponse:
    stmt = select(ThreatAnalysisRecord).where(ThreatAnalysisRecord.id == analysis_id)
    record = (await session.execute(stmt)).scalar_one_or_none()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis record '{analysis_id}' not found.",
        )

    evidence = [EvidenceItem(**item) for item in record.evidence_payload]
    decision = Decision(record.decision)
    provenance = ProvenanceType(record.provenance)

    return URLAnalysisResponse(
        analysis_id=record.id,
        input_validation_status="valid",
        safe_normalized_url=record.normalized_identifier,
        normalized_identifier=record.normalized_identifier,
        decision=decision,
        threat_score=record.threat_score,
        evidence=evidence,
        matched_indicators=[],
        engine_version=record.engine_version,
        policy_version=record.policy_version,
        confidence=record.confidence,
        provenance=provenance,
        explanation=f"Historic verdict recorded with decision: {record.decision.upper()}",
        fail_safe_applied=False,
        analyzed_at=record.created_at,
    )
