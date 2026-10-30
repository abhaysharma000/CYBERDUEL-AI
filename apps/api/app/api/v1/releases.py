"""Release Management REST API endpoints for eligibility, authorization, signing, rollouts, and rollbacks."""

import logging
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from cyberduel_contracts.enums import (
    ReleaseChannel,
    ReleaseStatus,
    RolloutStage,
)
from cyberduel_contracts.releases import (
    ReleaseEligibilityReport,
    RolloutState,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.auth import Role, UserProfile, get_current_user, require_permission
from apps.api.app.core.rate_limit import rate_limit_dependency
from apps.api.app.db.session import get_db_session
from apps.api.app.models.policies import CandidateDefenseRecord
from apps.api.app.models.releases import (
    ReleaseAuthorizationRecord,
    ReleaseRecord,
    RolloutStateRecord,
)
from apps.api.app.services.audit_service import AuditService
from apps.api.app.services.releases import (
    ReleaseApprovalError,
    ReleaseApprovalService,
    ReleaseEligibilityService,
    RollbackError,
    RollbackService,
    RolloutManager,
)

logger = logging.getLogger("api.releases")
router = APIRouter(prefix="/releases", tags=["Release Management"])

_eligibility_service = ReleaseEligibilityService()
_approval_service = ReleaseApprovalService()
_rollout_manager = RolloutManager()
_rollback_service = RollbackService()


class EligibilityCheckRequest(BaseModel):
    candidate_id: UUID
    evaluation_report_id: UUID


class ReleaseAuthorizeRequest(BaseModel):
    candidate_id: UUID
    evaluation_report_id: UUID
    policy_version: Annotated[str, Field(min_length=3, max_length=32)]
    target_channel: ReleaseChannel = ReleaseChannel.STABLE
    authorized_by: Annotated[str, Field(min_length=2, max_length=128)]
    rationale: Annotated[str, Field(min_length=5, max_length=2048)]
    rule_spec: dict[str, Any] | None = None
    threat_indicators: list[dict[str, Any]] | None = None
    scoring_thresholds: dict[str, float] | None = None
    min_client_version: str = "0.1.0"
    min_engine_version: str = "1.0.0"
    supported_platforms: list[str] | None = None
    release_notes: str = ""


class ReleaseSummaryResponse(BaseModel):
    release_id: UUID
    policy_version: str
    sequence_number: int
    channel: str
    status: str
    artifact_digest: str
    artifact_size_bytes: int
    publisher_key_id: str
    is_mandatory: bool
    is_rollback: bool
    rollback_target_version: str | None
    published_at: datetime | None
    expires_at: datetime
    rollout_stage: str
    rollout_percentage: float
    current_rollout_percentage: float | None = None
    rollout_phase: str | None = None
    is_paused: bool
    created_at: datetime | None = None


class ReleaseDetailResponse(BaseModel):
    release: ReleaseSummaryResponse
    manifest: dict[str, Any]
    authorizations: list[dict[str, Any]]
    rollout_metrics: dict[str, Any]


class RevokeReleaseRequest(BaseModel):
    reason: Annotated[str, Field(min_length=3, max_length=1024)]
    revoked_by: Annotated[str, Field(min_length=2, max_length=128)]


class RollbackRequest(BaseModel):
    regressed_release_id: UUID
    target_version: Annotated[str, Field(min_length=3, max_length=32)]
    authorized_by: Annotated[str, Field(min_length=2, max_length=128)]
    reason: Annotated[str, Field(min_length=5, max_length=1024)]


@router.post(
    "/eligibility",
    response_model=ReleaseEligibilityReport,
    dependencies=[Depends(rate_limit_dependency), Depends(require_permission("releases:read"))],
    summary="Check Candidate Defense Release Eligibility",
    description="Inspects candidate defense and its genuine evaluation report against quantitative acceptance criteria.",
)
async def check_candidate_eligibility(
    request: EligibilityCheckRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ReleaseEligibilityReport:
    """Verify whether a candidate defense proposal satisfies release eligibility criteria."""
    try:
        return await _eligibility_service.check_eligibility(
            session=session,
            candidate_id=request.candidate_id,
            evaluation_report_id=request.evaluation_report_id,
        )
    except Exception as e:
        logger.exception("Error checking release eligibility: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Eligibility check failed: {e}",
        ) from e


@router.post(
    "/authorize",
    response_model=ReleaseSummaryResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_dependency), Depends(require_permission("releases:manage"))],
    summary="Authorize and Stage Release",
    description="Explicit administrative deployment authorization. Validates eligibility, builds declarative bundle, signs manifest with Ed25519, and stages the release.",
)
async def authorize_release(
    request: ReleaseAuthorizeRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[UserProfile, Depends(get_current_user)],
) -> ReleaseSummaryResponse:
    """Authorize production release for an eligible candidate."""
    # If rule_spec is omitted, fetch it from candidate defense record
    rule_spec = request.rule_spec
    if not rule_spec:
        cand_stmt = select(CandidateDefenseRecord).where(
            CandidateDefenseRecord.id == request.candidate_id
        )
        candidate = (await session.execute(cand_stmt)).scalar_one_or_none()
        if not candidate:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Candidate defense '{request.candidate_id}' not found",
            )
        rule_spec = candidate.rule_spec or {}

    try:
        release, auth = await _approval_service.authorize_and_stage_release(
            session=session,
            candidate_id=request.candidate_id,
            evaluation_report_id=request.evaluation_report_id,
            policy_version=request.policy_version,
            target_channel=request.target_channel,
            authorized_by=request.authorized_by,
            rationale=request.rationale,
            rule_spec=rule_spec,
            threat_indicators=request.threat_indicators,
            scoring_thresholds=request.scoring_thresholds,
            min_client_version=request.min_client_version,
            min_engine_version=request.min_engine_version,
            supported_platforms=request.supported_platforms,
            release_notes=request.release_notes,
        )

        try:
            await AuditService.record_event(
                session=session,
                actor=current_user.username,
                action="release.authorize",
                target_id=str(release.id),
                target_type="release",
                outcome="success",
                metadata={
                    "policy_version": release.policy_version,
                    "target_channel": release.channel,
                    "authorized_by": request.authorized_by,
                    "artifact_digest": release.artifact_digest,
                },
            )
        except Exception as audit_err:
            logger.warning("Audit log recording failed: %s", audit_err)

        await session.commit()

        # Load rollout state
        rollout_stmt = select(RolloutStateRecord).where(RolloutStateRecord.release_id == release.id)
        rollout = (await session.execute(rollout_stmt)).scalar_one_or_none()

        return ReleaseSummaryResponse(
            release_id=release.id,
            policy_version=release.policy_version,
            sequence_number=release.sequence_number,
            channel=release.channel,
            status=release.status,
            artifact_digest=release.artifact_digest,
            artifact_size_bytes=release.artifact_size_bytes,
            publisher_key_id=release.publisher_key_id,
            is_mandatory=release.is_mandatory,
            is_rollback=release.is_rollback,
            rollback_target_version=release.rollback_target_version,
            published_at=release.published_at,
            expires_at=release.expires_at,
            rollout_stage=rollout.stage if rollout else RolloutStage.INTERNAL.value,
            rollout_percentage=rollout.rollout_percentage if rollout else 0.0,
            current_rollout_percentage=rollout.rollout_percentage if rollout else 0.0,
            rollout_phase=rollout.stage if rollout else "internal",
            is_paused=rollout.is_paused if rollout else False,
            created_at=release.created_at if hasattr(release, "created_at") else None,
        )
    except ReleaseApprovalError as e:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        await session.rollback()
        logger.exception("Error authorizing release: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authorization failed: {e}",
        ) from e


@router.get(
    "",
    response_model=list[ReleaseSummaryResponse],
    dependencies=[Depends(rate_limit_dependency), Depends(require_permission("releases:read"))],
    summary="List Releases",
    description="Lists all security policy releases ordered by monotonic sequence number.",
)
async def list_releases(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    channel: str | None = Query(None, description="Filter by channel (e.g. stable, canary)"),
    release_status: str | None = Query(None, alias="status", description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
) -> list[ReleaseSummaryResponse]:
    """Retrieve releases."""
    stmt = (
        select(ReleaseRecord, RolloutStateRecord)
        .outerjoin(RolloutStateRecord, RolloutStateRecord.release_id == ReleaseRecord.id)
        .order_by(ReleaseRecord.sequence_number.desc())
        .limit(limit)
    )
    if channel:
        stmt = stmt.where(ReleaseRecord.channel == channel)
    if release_status:
        stmt = stmt.where(ReleaseRecord.status == release_status)

    results = (await session.execute(stmt)).all()
    out = []
    for rel, rollout in results:
        out.append(
            ReleaseSummaryResponse(
                release_id=rel.id,
                policy_version=rel.policy_version,
                sequence_number=rel.sequence_number,
                channel=rel.channel,
                status=rel.status,
                artifact_digest=rel.artifact_digest,
                artifact_size_bytes=rel.artifact_size_bytes,
                publisher_key_id=rel.publisher_key_id,
                is_mandatory=rel.is_mandatory,
                is_rollback=rel.is_rollback,
                rollback_target_version=rel.rollback_target_version,
                published_at=rel.published_at,
                expires_at=rel.expires_at,
                rollout_stage=rollout.stage if rollout else RolloutStage.INTERNAL.value,
                rollout_percentage=rollout.rollout_percentage if rollout else 0.0,
                current_rollout_percentage=rollout.rollout_percentage if rollout else 0.0,
                rollout_phase=rollout.stage if rollout else "internal",
                is_paused=rollout.is_paused if rollout else False,
                created_at=rel.created_at if hasattr(rel, "created_at") else None,
            )
        )
    return out


@router.get(
    "/{release_id}",
    response_model=ReleaseDetailResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(require_permission("releases:read"))],
    summary="Get Release Details",
    description="Retrieves full release metadata, manifest, authorizations, and rollout metrics.",
)
async def get_release(
    release_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ReleaseDetailResponse:
    """Retrieve complete release record details."""
    stmt = (
        select(ReleaseRecord, RolloutStateRecord)
        .outerjoin(RolloutStateRecord, RolloutStateRecord.release_id == ReleaseRecord.id)
        .where(ReleaseRecord.id == release_id)
    )
    res = (await session.execute(stmt)).first()
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Release '{release_id}' not found",
        )
    rel, rollout = res

    # Fetch authorizations
    auth_stmt = select(ReleaseAuthorizationRecord).where(
        ReleaseAuthorizationRecord.release_id == release_id
    )
    auths = (await session.execute(auth_stmt)).scalars().all()
    auth_list = [
        {
            "id": str(a.id),
            "authorized_by": a.authorized_by,
            "rationale": a.rationale,
            "target_channel": a.target_channel,
            "authorized_at": a.authorized_at.isoformat(),
        }
        for a in auths
    ]

    summary = ReleaseSummaryResponse(
        release_id=rel.id,
        policy_version=rel.policy_version,
        sequence_number=rel.sequence_number,
        channel=rel.channel,
        status=rel.status,
        artifact_digest=rel.artifact_digest,
        artifact_size_bytes=rel.artifact_size_bytes,
        publisher_key_id=rel.publisher_key_id,
        is_mandatory=rel.is_mandatory,
        is_rollback=rel.is_rollback,
        rollback_target_version=rel.rollback_target_version,
        published_at=rel.published_at,
        expires_at=rel.expires_at,
        rollout_stage=rollout.stage if rollout else RolloutStage.INTERNAL.value,
        rollout_percentage=rollout.rollout_percentage if rollout else 0.0,
        current_rollout_percentage=rollout.rollout_percentage if rollout else 0.0,
        rollout_phase=rollout.stage if rollout else "internal",
        is_paused=rollout.is_paused if rollout else False,
        created_at=rel.created_at if hasattr(rel, "created_at") else None,
    )

    metrics = {
        "total_targeted_clients": rollout.total_targeted_clients if rollout else 0,
        "successful_installs": rollout.successful_installs if rollout else 0,
        "failed_installs": rollout.failed_installs if rollout else 0,
        "rollback_count": rollout.rollback_count if rollout else 0,
        "failure_rate": rollout.failure_rate if rollout else 0.0,
    }

    return ReleaseDetailResponse(
        release=summary,
        manifest=rel.manifest_payload,
        authorizations=auth_list,
        rollout_metrics=metrics,
    )


@router.post(
    "/{release_id}/advance",
    response_model=RolloutState,
    dependencies=[Depends(rate_limit_dependency), Depends(require_permission("releases:manage"))],
    summary="Advance Rollout Stage",
    description="Advances the release rollout to the next stage (e.g. internal -> canary_10 -> canary_25 -> canary_50 -> general_availability).",
)
async def advance_rollout(
    release_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[UserProfile, Depends(get_current_user)],
    target_stage: RolloutStage | None = None,
) -> RolloutState:
    """Advance staged rollout progression."""
    try:
        state = await _rollout_manager.advance_stage(session, release_id, target_stage=target_stage)
        try:
            await AuditService.record_event(
                session=session,
                actor=current_user.username,
                action="release.advance_rollout",
                target_id=str(release_id),
                target_type="release",
                outcome="success",
                metadata={
                    "target_stage": target_stage.value if target_stage else state.stage.value,
                    "rollout_percentage": state.rollout_percentage,
                },
            )
        except Exception as audit_err:
            logger.warning("Audit log recording failed: %s", audit_err)

        await session.commit()
        return state
    except Exception as e:
        await session.rollback()
        logger.exception("Error advancing rollout: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to advance rollout: {e}",
        ) from e


@router.post(
    "/{release_id}/pause",
    response_model=RolloutState,
    dependencies=[Depends(rate_limit_dependency), Depends(require_permission("releases:manage"))],
    summary="Pause Rollout",
    description="Halts further distribution of the specified release.",
)
async def pause_rollout(
    release_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[UserProfile, Depends(get_current_user)],
) -> RolloutState:
    """Pause rollout."""
    try:
        state = await _rollout_manager.pause_rollout(session, release_id)
        try:
            await AuditService.record_event(
                session=session,
                actor=current_user.username,
                action="release.pause_rollout",
                target_id=str(release_id),
                target_type="release",
                outcome="success",
            )
        except Exception as audit_err:
            logger.warning("Audit log recording failed: %s", audit_err)

        await session.commit()
        return state
    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause rollout: {e}",
        ) from e


@router.post(
    "/{release_id}/resume",
    response_model=RolloutState,
    dependencies=[Depends(rate_limit_dependency), Depends(require_permission("releases:manage"))],
    summary="Resume Rollout",
    description="Resumes a previously paused release rollout.",
)
async def resume_rollout(
    release_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[UserProfile, Depends(get_current_user)],
) -> RolloutState:
    """Resume rollout."""
    try:
        state = await _rollout_manager.resume_rollout(session, release_id)
        try:
            await AuditService.record_event(
                session=session,
                actor=current_user.username,
                action="release.resume_rollout",
                target_id=str(release_id),
                target_type="release",
                outcome="success",
            )
        except Exception as audit_err:
            logger.warning("Audit log recording failed: %s", audit_err)

        await session.commit()
        return state
    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resume rollout: {e}",
        ) from e


@router.post(
    "/{release_id}/revoke",
    response_model=ReleaseSummaryResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(require_permission("releases:manage"))],
    summary="Revoke Policy Release",
    description="Marks a policy release as revoked and immediately halts rollout.",
)
async def revoke_release(
    release_id: UUID,
    request: RevokeReleaseRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[UserProfile, Depends(get_current_user)],
) -> ReleaseSummaryResponse:
    """Revoke release immediately."""
    stmt = (
        select(ReleaseRecord, RolloutStateRecord)
        .outerjoin(RolloutStateRecord, RolloutStateRecord.release_id == ReleaseRecord.id)
        .where(ReleaseRecord.id == release_id)
    )
    res = (await session.execute(stmt)).first()
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Release '{release_id}' not found",
        )
    rel, rollout = res

    rel.status = ReleaseStatus.REVOKED.value
    rel.release_notes = f"[REVOKED by {request.revoked_by}]: {request.reason}\n" + (
        rel.release_notes or ""
    )
    if rollout:
        rollout.is_paused = True
        rollout.stage = RolloutStage.HALTED.value

    try:
        await AuditService.record_event(
            session=session,
            actor=current_user.username,
            action="release.revoke",
            target_id=str(release_id),
            target_type="release",
            outcome="success",
            reason=request.reason,
            metadata={"revoked_by": request.revoked_by},
        )
    except Exception as audit_err:
        logger.warning("Audit log recording failed: %s", audit_err)

    await session.commit()
    return ReleaseSummaryResponse(
        release_id=rel.id,
        policy_version=rel.policy_version,
        sequence_number=rel.sequence_number,
        channel=rel.channel,
        status=rel.status,
        artifact_digest=rel.artifact_digest,
        artifact_size_bytes=rel.artifact_size_bytes,
        publisher_key_id=rel.publisher_key_id,
        is_mandatory=rel.is_mandatory,
        is_rollback=rel.is_rollback,
        rollback_target_version=rel.rollback_target_version,
        published_at=rel.published_at,
        expires_at=rel.expires_at,
        rollout_stage=rollout.stage if rollout else RolloutStage.HALTED.value,
        rollout_percentage=rollout.rollout_percentage if rollout else 0.0,
        current_rollout_percentage=rollout.rollout_percentage if rollout else 0.0,
        rollout_phase=rollout.stage if rollout else "halted",
        is_paused=True,
        created_at=rel.created_at if hasattr(rel, "created_at") else None,
    )


@router.post(
    "/rollback",
    response_model=ReleaseSummaryResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_dependency), Depends(require_permission("releases:manage"))],
    summary="Execute Emergency Rollback",
    description="Reverts a channel to a known-good historical release, assigning a new monotonic sequence number to ensure anti-replay acceptance by edge clients.",
)
async def execute_rollback(
    request: RollbackRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[UserProfile, Depends(get_current_user)],
) -> ReleaseSummaryResponse:
    """Execute emergency signed rollback."""
    try:
        rec = await _rollback_service.execute_rollback(
            session=session,
            regressed_release_id=request.regressed_release_id,
            target_version=request.target_version,
            authorized_by=request.authorized_by,
            reason=request.reason,
        )

        try:
            await AuditService.record_event(
                session=session,
                actor=current_user.username,
                action="release.emergency_rollback",
                target_id=str(rec.id),
                target_type="release",
                outcome="success",
                reason=request.reason,
                metadata={
                    "regressed_release_id": str(request.regressed_release_id),
                    "target_version": request.target_version,
                    "authorized_by": request.authorized_by,
                },
            )
        except Exception as audit_err:
            logger.warning("Audit log recording failed: %s", audit_err)

        await session.commit()

        # Fetch rollout state
        rollout_stmt = select(RolloutStateRecord).where(RolloutStateRecord.release_id == rec.id)
        rollout = (await session.execute(rollout_stmt)).scalar_one_or_none()

        return ReleaseSummaryResponse(
            release_id=rec.id,
            policy_version=rec.policy_version,
            sequence_number=rec.sequence_number,
            channel=rec.channel,
            status=rec.status,
            artifact_digest=rec.artifact_digest,
            artifact_size_bytes=rec.artifact_size_bytes,
            publisher_key_id=rec.publisher_key_id,
            is_mandatory=rec.is_mandatory,
            is_rollback=rec.is_rollback,
            rollback_target_version=rec.rollback_target_version,
            published_at=rec.published_at,
            expires_at=rec.expires_at,
            rollout_stage=rollout.stage if rollout else RolloutStage.GENERAL_AVAILABILITY.value,
            rollout_percentage=rollout.rollout_percentage if rollout else 100.0,
            current_rollout_percentage=rollout.rollout_percentage if rollout else 100.0,
            rollout_phase=rollout.stage if rollout else "general_availability",
            is_paused=rollout.is_paused if rollout else False,
            created_at=rec.created_at if hasattr(rec, "created_at") else None,
        )
    except RollbackError as e:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        await session.rollback()
        logger.exception("Error executing rollback: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rollback execution failed: {e}",
        ) from e
