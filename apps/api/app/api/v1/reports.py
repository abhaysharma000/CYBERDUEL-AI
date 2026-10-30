"""Privacy-conscious threat observation reporting endpoints."""

from uuid import uuid4

from cyberduel_contracts.enums import ObservationSource
from cyberduel_contracts.observation import ThreatObservationReport
from cyberduel_threat_intel.validator import URLValidator
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.rate_limit import rate_limit_dependency
from apps.api.app.db.session import get_db_session
from apps.api.app.services.threat_observation_service import (
    ThreatObservationService,
)

router = APIRouter(prefix="/threat-reports", tags=["Threat Reporting"])


class ThreatReportSubmissionRequest(BaseModel):
    """User or client report submitting a suspicious resource for laboratory investigation."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=3, max_length=4096, description="Reported resource URL")
    reported_category: str = Field(
        default="phishing",
        description="User-observed threat category: phishing, malware, scam, or false_positive",
    )
    user_notes: str | None = Field(
        default=None,
        max_length=512,
        description="Optional voluntary context (sanitized of personal data)",
    )
    client_id: str | None = Field(default=None, max_length=128)


class ThreatReportReceipt(BaseModel):
    report_id: str
    status: str
    target_digest: str
    message: str


@router.post(
    "",
    response_model=ThreatReportReceipt,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Submit Threat Report for Investigation",
    description=(
        "Safely ingests a suspicious indicator report. Note: User reports are strictly treated as evidence "
        "for subsequent laboratory investigation and are never treated as automatic proof of maliciousness."
    ),
)
async def submit_threat_report(
    report: ThreatReportSubmissionRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ThreatReportReceipt:
    # 1. Normalize and extract safe target digest (strip any credentials)
    val = URLValidator.validate(report.url)
    if val.is_valid and val.normalized:
        target_digest = val.normalized.url_sha256
        safe_domain = val.normalized.domain
    else:
        target_digest = "unparseable_url_" + uuid4().hex[:16]
        safe_domain = "unknown"

    # 2. Ingest via ThreatObservationService
    obs_report = ThreatObservationReport(
        observation_id=uuid4(),
        source=ObservationSource.BROWSER_EXTENSION
        if report.client_id
        else ObservationSource.EXTERNAL_FEED,
        normalized_target=target_digest,
        engine_version="0.2.0",
        policy_version="2026.10.1",
        telemetry_summary={
            "reported_category": report.reported_category,
            "domain": safe_domain,
            "has_user_notes": bool(report.user_notes),
        },
    )

    service = ThreatObservationService(session=session)
    ingest_res = await service.ingest_observation(obs_report)

    return ThreatReportReceipt(
        report_id=ingest_res["observation_id"],
        status=ingest_res["status"],
        target_digest=target_digest,
        message=ingest_res["message"],
    )
