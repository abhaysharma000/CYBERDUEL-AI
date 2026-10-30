"""Edge client update protocol endpoints: update discovery, signed manifest delivery, artifact downloading, and telemetry receipts."""

import logging
from typing import Annotated

from cyberduel_contracts.enums import ReleaseStatus
from cyberduel_contracts.releases import ReleaseManifest, TrustAnchorSet
from cyberduel_contracts.updates import (
    UpdateAcknowledgement,
    UpdateCheckRequest,
    UpdateCheckResponse,
)
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi import Path as FastApiPath
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.rate_limit import rate_limit_dependency
from apps.api.app.db.session import get_db_session
from apps.api.app.models.releases import ReleaseRecord
from apps.api.app.services.releases import (
    ClientAcknowledgementService,
    SigningKeyManager,
    UpdateDistributionService,
)

logger = logging.getLogger("api.updates")
router = APIRouter(prefix="/updates", tags=["Updates"])

_distribution_service = UpdateDistributionService()
_ack_service = ClientAcknowledgementService()
_key_manager = SigningKeyManager()


class AcknowledgementResponse(BaseModel):
    acknowledgement_id: str
    status: str


class RevocationsResponse(BaseModel):
    revoked_keys: list[dict]
    revoked_releases: list[str]


@router.post(
    "/check",
    response_model=UpdateCheckResponse,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Check for Defensive Policy Updates",
    description="Queries whether an approved, signed policy update is available for the given edge client.",
)
async def check_for_updates(
    request: UpdateCheckRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> UpdateCheckResponse:
    """Evaluate client eligibility and return update response pointing to latest signed manifest."""
    try:
        resp = await _distribution_service.check_for_updates(session, request)
        await session.commit()
        return resp
    except Exception as e:
        logger.exception("Error checking for updates: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Update check failed: {e}",
        ) from e


@router.get(
    "/manifests/{version_or_id}",
    response_model=ReleaseManifest,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Retrieve Signed Release Manifest",
    description="Fetches the cryptographically signed release manifest describing a policy update.",
)
async def get_manifest(
    version_or_id: Annotated[
        str,
        FastApiPath(
            description="Release version string or UUID",
            pattern=r"^[a-zA-Z0-9.\-_]{1,64}$",
            max_length=64,
        ),
    ],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ReleaseManifest:
    """Download signed release manifest for client-side cryptographic verification."""
    try:
        return await _distribution_service.get_manifest(session, version_or_id)
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.exception("Error retrieving manifest %s: %s", version_or_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve manifest: {e}",
        ) from e


@router.get(
    "/artifacts/{digest}",
    dependencies=[Depends(rate_limit_dependency)],
    summary="Download Immutable Policy Bundle",
    description="Downloads the canonical JSON policy bundle verified by the given SHA-256 digest.",
)
async def get_artifact(
    digest: Annotated[
        str, FastApiPath(description="SHA-256 digest of artifact", pattern="^[a-fA-F0-9]{64}$")
    ],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> Response:
    """Download immutable policy bundle bytes."""
    try:
        content_bytes, _ = await _distribution_service.get_artifact_bytes(session, digest)
        return Response(
            content=content_bytes,
            media_type="application/json",
            headers={
                "ETag": f'"{digest}"',
                "Cache-Control": "public, max-age=31536000, immutable",
            },
        )
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.exception("Error retrieving artifact %s: %s", digest, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve artifact: {e}",
        ) from e


@router.post(
    "/ack",
    response_model=AcknowledgementResponse,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Acknowledge Update Delivery Outcome",
    description="Records whether an edge client successfully installed, failed, or rolled back an update.",
)
async def acknowledge_update(
    ack: UpdateAcknowledgement,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> AcknowledgementResponse:
    """Record receipt from edge client."""
    try:
        rec = await _ack_service.record_acknowledgement(session, ack)
        await session.commit()
        return AcknowledgementResponse(
            acknowledgement_id=str(rec.id),
            status="recorded",
        )
    except Exception as e:
        logger.exception("Error recording acknowledgement: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record acknowledgement: {e}",
        ) from e


@router.get(
    "/trust-anchors",
    response_model=TrustAnchorSet,
    dependencies=[Depends(rate_limit_dependency)],
    summary="Retrieve Public Trust Anchors",
    description="Returns public verification keys and revocation lists used by edge clients to authenticate manifests.",
)
async def get_trust_anchors(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> TrustAnchorSet:
    """Retrieve public Ed25519 verification keys."""
    try:
        return await _key_manager.get_trust_anchors(session)
    except Exception as e:
        logger.exception("Error fetching trust anchors: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch trust anchors: {e}",
        ) from e


@router.get(
    "/revocations",
    response_model=RevocationsResponse,
    dependencies=[Depends(rate_limit_dependency)],
    summary="List Revoked Keys and Policy Releases",
    description="Retrieves a list of revoked signing keys and compromised policy versions.",
)
async def get_revocations(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> RevocationsResponse:
    """Retrieve all revoked keys and releases."""
    try:
        anchors = await _key_manager.get_trust_anchors(session)
        revoked_keys_list = [k.model_dump(mode="json") for k in anchors.revoked_keys]

        # Fetch revoked releases
        stmt = select(ReleaseRecord.policy_version).where(
            ReleaseRecord.status.in_([ReleaseStatus.REVOKED.value, ReleaseStatus.ROLLED_BACK.value])
        )
        result = await session.execute(stmt)
        revoked_releases_list = list(result.scalars().all())

        return RevocationsResponse(
            revoked_keys=revoked_keys_list,
            revoked_releases=revoked_releases_list,
        )
    except Exception as e:
        logger.exception("Error fetching revocations: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch revocations: {e}",
        ) from e
