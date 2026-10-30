"""Threat classification and resource analysis endpoints."""

from cyberduel_contracts.analysis import (
    ResourceAnalysisRequest,
    ThreatAnalysisResult,
)
from fastapi import APIRouter, Depends

from apps.api.app.core.rate_limit import rate_limit_dependency
from apps.api.app.providers.base import BaseThreatClassificationProvider
from apps.api.app.providers.factory import get_ai_provider

router = APIRouter(prefix="/analysis", tags=["Analysis"])


@router.post(
    "/evaluate",
    response_model=ThreatAnalysisResult,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Evaluate Resource Threat Level",
    description="Analyzes a normalized resource identifier or URL and returns a calibrated threat score and decision.",
)
async def evaluate_resource(
    request: ResourceAnalysisRequest,
    provider: BaseThreatClassificationProvider = Depends(get_ai_provider),
) -> ThreatAnalysisResult:
    result = await provider.classify_resource(
        normalized_identifier=request.normalized_identifier,
        resource_url=request.resource_url,
        context=request.context,
    )
    return result
