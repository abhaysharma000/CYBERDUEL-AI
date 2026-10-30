"""Constructs and signs release manifests with monotonic sequence numbers and compatibility metadata."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from cyberduel_contracts.enums import ReleaseChannel, ReleaseStatus
from cyberduel_contracts.releases import ReleaseManifest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.releases import ReleaseRecord
from apps.api.app.services.releases.signing import ReleaseSigningService


class ReleaseManifestBuilder:
    """Builds cryptographically verifiable release manifests."""

    def __init__(self, signing_service: ReleaseSigningService | None = None) -> None:
        self.signing_service = signing_service or ReleaseSigningService()

    async def get_next_sequence_number(self, session: AsyncSession) -> int:
        """Allocate next strictly monotonic sequence number across all published/staged releases."""
        stmt = select(func.max(ReleaseRecord.sequence_number))
        result = await session.execute(stmt)
        max_seq = result.scalar()
        return (max_seq or 0) + 1

    async def build_signed_manifest(
        self,
        session: AsyncSession,
        policy_version: str,
        artifact_digest: str,
        artifact_size_bytes: int,
        artifact_url: str,
        publisher_key_id: str,
        channel: ReleaseChannel = ReleaseChannel.STABLE,
        status: ReleaseStatus = ReleaseStatus.STAGED,
        min_client_version: str = "0.1.0",
        max_client_version: str | None = None,
        min_engine_version: str = "1.0.0",
        supported_platforms: list[str] | None = None,
        expires_at: datetime | None = None,
        is_mandatory: bool = False,
        is_rollback: bool = False,
        rollback_target_version: str | None = None,
        release_notes: str = "",
        release_id: UUID | None = None,
        sequence_number: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ReleaseManifest:
        """Create canonical manifest dictionary, sign it with private key, and return ReleaseManifest."""
        if sequence_number is None:
            sequence_number = await self.get_next_sequence_number(session)

        now = datetime.now(UTC)
        expiry = expires_at or datetime(now.year + 1, now.month, now.day, tzinfo=UTC)
        platforms = supported_platforms or ["browser_extension", "mobile_app", "agent_node"]

        manifest_obj = ReleaseManifest(
            release_id=release_id or uuid4(),
            policy_version=policy_version,
            sequence_number=sequence_number,
            channel=channel,
            status=status,
            published_at=now,
            expires_at=expiry,
            min_client_version=min_client_version,
            max_client_version=max_client_version,
            min_engine_version=min_engine_version,
            supported_platforms=platforms,
            artifact_digest=artifact_digest,
            artifact_size_bytes=artifact_size_bytes,
            artifact_url=artifact_url,
            publisher_key_id=publisher_key_id,
            signature="00" * 32,  # temporary placeholder for model validation
            is_mandatory=is_mandatory,
            is_rollback=is_rollback,
            rollback_target_version=rollback_target_version,
            release_notes=release_notes,
            metadata=metadata or {},
        )

        manifest_payload = manifest_obj.model_dump(mode="json")
        signature_hex = self.signing_service.sign_manifest_payload(
            manifest_payload, publisher_key_id
        )

        return manifest_obj.model_copy(update={"signature": signature_hex})
