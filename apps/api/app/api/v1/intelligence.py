"""Threat intelligence management and status endpoints."""

from typing import Annotated, Any

from cyberduel_threat_intel.heuristics import URLHeuristicAnalyzer
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.config import Settings, get_settings
from apps.api.app.db.session import get_db_session
from apps.api.app.repositories.threat_intel_repository import ThreatIntelRepository

router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence"])


class IntelligenceStatusResponse(BaseModel):
    status: str
    active_indicators: int
    registered_heuristic_rules: int
    policy_version: str
    engine_mode: str


class IndicatorImportItem(BaseModel):
    indicator_type: str
    normalized_value: str
    classification: str
    source: str
    severity: str = "high"
    confidence: float = 0.95


class IndicatorImportRequest(BaseModel):
    indicators: list[IndicatorImportItem] = Field(min_length=1, max_length=1000)


class IndicatorImportResponse(BaseModel):
    imported_count: int
    message: str


def verify_admin_access(
    x_admin_key: Annotated[str | None, Header()] = None,
    settings: Settings = Depends(get_settings),
) -> None:
    """Ensure privileged intelligence modification operations are authorized."""
    if settings.is_production and (not x_admin_key or x_admin_key != settings.SECRET_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: valid X-Admin-Key required for threat intelligence ingestion.",
        )


@router.get(
    "/status",
    response_model=IntelligenceStatusResponse,
    summary="Get Threat Intelligence Status",
    description="Reports the count of active intelligence indicators, registered heuristic rules, and active policy version.",
)
async def get_intelligence_status(
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> IntelligenceStatusResponse:
    repo = ThreatIntelRepository(session=session)
    indicator_count = await repo.count()
    analyzer = URLHeuristicAnalyzer()
    rule_count = len(analyzer.rules)

    return IntelligenceStatusResponse(
        status="operational",
        active_indicators=indicator_count,
        registered_heuristic_rules=rule_count,
        policy_version="2026.10.1",
        engine_mode="local_hybrid",
    )


@router.post(
    "/import",
    response_model=IndicatorImportResponse,
    dependencies=[Depends(verify_admin_access)],
    summary="Import Threat Intelligence Indicators",
    description="Administratively imports verified threat intelligence indicators into the repository.",
)
async def import_indicators(
    request: IndicatorImportRequest,
    session: AsyncSession = Depends(get_db_session),
) -> IndicatorImportResponse:
    repo = ThreatIntelRepository(session=session)
    count = 0
    for item in request.indicators:
        await repo.add_indicator(
            indicator_type=item.indicator_type,
            normalized_value=item.normalized_value,
            classification=item.classification,
            source=item.source,
            severity=item.severity,
            confidence=item.confidence,
        )
        count += 1

    return IndicatorImportResponse(
        imported_count=count,
        message=f"Successfully imported {count} threat indicators into the intelligence repository.",
    )


@router.get(
    "/indicators",
    summary="List Threat Intelligence Indicators",
    description="Returns verified or provisional threat indicators for intelligence inspection.",
)
async def list_indicators(
    session: AsyncSession = Depends(get_db_session),
    limit: int = 50,
) -> list[dict[str, Any]]:
    from sqlalchemy import select
    from apps.api.app.models.indicators import ThreatIndicatorRecord

    stmt = select(ThreatIndicatorRecord).order_by(ThreatIndicatorRecord.created_at.desc()).limit(limit)
    res = await session.execute(stmt)
    records = res.scalars().all()
    return [
        {
            "id": str(r.id),
            "indicator_type": r.indicator_type,
            "value": r.normalized_value,
            "pattern": r.normalized_value,
            "classification": r.classification,
            "severity": r.severity,
            "confidence": r.confidence if r.confidence is not None else 0.95,
            "source": r.source,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in records
    ]
