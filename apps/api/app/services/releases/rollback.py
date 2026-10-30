"""Controlled emergency rollback service generating signed rollback manifests with monotonic sequences."""

from datetime import UTC, datetime
from uuid import UUID

from cyberduel_contracts.enums import (
    ReleaseChannel,
    ReleaseStatus,
    RolloutStage,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.releases import (
    ReleaseAuthorizationRecord,
    ReleaseRecord,
    RolloutStateRecord,
)
from apps.api.app.services.releases.bundle_builder import PolicyBundleBuilder
from apps.api.app.services.releases.key_manager import SigningKeyManager
from apps.api.app.services.releases.manifest_builder import ReleaseManifestBuilder
from apps.api.app.services.releases.storage import ArtifactStorageService


class RollbackError(Exception):
    """Raised when rollback prerequisites or authorization fail."""


class RollbackService:
    """Creates authenticated, verifiable rollback releases targeting known-good historical policies."""

    def __init__(
        self,
        bundle_builder: PolicyBundleBuilder | None = None,
        manifest_builder: ReleaseManifestBuilder | None = None,
        storage_service: ArtifactStorageService | None = None,
        key_manager: SigningKeyManager | None = None,
    ) -> None:
        self.bundle_builder = bundle_builder or PolicyBundleBuilder()
        self.key_manager = key_manager or SigningKeyManager()
        from apps.api.app.services.releases.signing import ReleaseSigningService

        signing_svc = ReleaseSigningService(key_manager=self.key_manager)
        self.manifest_builder = manifest_builder or ReleaseManifestBuilder(
            signing_service=signing_svc
        )
        self.storage_service = storage_service or ArtifactStorageService()

    async def execute_rollback(
        self,
        session: AsyncSession,
        regressed_release_id: UUID,
        target_version: str,
        authorized_by: str,
        reason: str,
    ) -> ReleaseRecord:
        """Create an emergency signed rollback release to revert clients to target_version."""
        # 1. Fetch the regressed release
        reg_stmt = select(ReleaseRecord).where(ReleaseRecord.id == regressed_release_id)
        regressed_release = (await session.execute(reg_stmt)).scalar_one_or_none()
        if not regressed_release:
            raise RollbackError(f"Regressed release '{regressed_release_id}' not found")

        # 2. Fetch target known-good release
        target_stmt = select(ReleaseRecord).where(ReleaseRecord.policy_version == target_version)
        target_release = (await session.execute(target_stmt)).scalar_one_or_none()
        if not target_release:
            raise RollbackError(f"Target rollback version '{target_version}' not found")

        # 3. Mark regressed release as rolled_back
        regressed_release.status = ReleaseStatus.ROLLED_BACK.value

        # 4. Allocate new strictly monotonic sequence number
        new_sequence = await self.manifest_builder.get_next_sequence_number(session)

        # 5. Formulate Rollback Policy Version string
        now = datetime.now(UTC)
        rollback_version = f"{target_version}-rb{now.strftime('%H%M%S')}"

        # 6. Re-package target declarative bundle with new sequence and rollback metadata
        target_bundle_payload = dict(target_release.bundle_payload)
        rule_spec = {
            "rules": target_bundle_payload.get("rules", []),
            "warn_threshold": target_bundle_payload.get("scoring_thresholds", {}).get(
                "warn_threshold", 0.50
            ),
            "block_threshold": target_bundle_payload.get("scoring_thresholds", {}).get(
                "block_threshold", 0.85
            ),
            "feature_weights": target_bundle_payload.get("feature_weights", {}),
        }

        bundle, bundle_bytes, artifact_digest = self.bundle_builder.build_bundle(
            policy_version=rollback_version,
            sequence_number=new_sequence,
            rule_spec=rule_spec,
            threat_indicators=target_bundle_payload.get("threat_indicators", []),
            scoring_thresholds=target_bundle_payload.get("scoring_thresholds"),
            metadata={
                "is_rollback": True,
                "reverted_from_version": regressed_release.policy_version,
                "target_known_good_version": target_version,
                "authorized_by": authorized_by,
                "reason": reason,
            },
        )

        # 7. Store Artifact Immutably
        filename_hint = f"policy-{rollback_version}-{artifact_digest[:12]}.json"
        saved_path, _ = self.storage_service.store_artifact(
            artifact_bytes=bundle_bytes,
            expected_digest=artifact_digest,
            filename_hint=filename_hint,
        )
        artifact_url = f"/api/v1/updates/artifacts/{artifact_digest}"

        # 8. Sign with Active Key
        active_key = await self.key_manager.get_active_key(session)
        publisher_key_id = active_key.key_id

        manifest = await self.manifest_builder.build_signed_manifest(
            session=session,
            policy_version=rollback_version,
            artifact_digest=artifact_digest,
            artifact_size_bytes=len(bundle_bytes),
            artifact_url=artifact_url,
            publisher_key_id=publisher_key_id,
            channel=ReleaseChannel(regressed_release.channel),
            status=ReleaseStatus.PUBLISHED,
            min_client_version=target_release.min_client_version,
            min_engine_version=target_release.min_engine_version,
            supported_platforms=target_release.supported_platforms,
            expires_at=bundle.expires_at,
            is_mandatory=True,
            is_rollback=True,
            rollback_target_version=target_version,
            release_notes=f"EMERGENCY ROLLBACK: Reverting {regressed_release.policy_version} to {target_version}. Reason: {reason}",
            sequence_number=new_sequence,
        )

        # 9. Persist Rollback Release Record
        rollback_record = ReleaseRecord(
            policy_version=rollback_version,
            sequence_number=new_sequence,
            channel=regressed_release.channel,
            candidate_id=target_release.candidate_id,
            evaluation_report_id=target_release.evaluation_report_id,
            status=ReleaseStatus.PUBLISHED.value,
            min_client_version=target_release.min_client_version,
            max_client_version=target_release.max_client_version,
            min_engine_version=target_release.min_engine_version,
            supported_platforms=target_release.supported_platforms,
            artifact_path=str(saved_path),
            artifact_digest=artifact_digest,
            artifact_size_bytes=len(bundle_bytes),
            publisher_key_id=publisher_key_id,
            signature=manifest.signature,
            manifest_payload=manifest.model_dump(mode="json"),
            bundle_payload=bundle.model_dump(mode="json"),
            published_at=now,
            expires_at=bundle.expires_at,
            is_mandatory=True,
            is_rollback=True,
            rollback_target_version=target_version,
            release_notes=manifest.release_notes,
        )
        session.add(rollback_record)
        await session.flush()

        # 10. Record Authorization
        auth_record = ReleaseAuthorizationRecord(
            release_id=rollback_record.id,
            candidate_id=target_release.candidate_id or rollback_record.id,
            evaluation_report_id=target_release.evaluation_report_id or rollback_record.id,
            policy_version=rollback_version,
            target_channel=regressed_release.channel,
            authorized_by=authorized_by,
            rationale=f"Rollback execution: {reason}",
            authorized_at=now,
        )
        session.add(auth_record)

        # 11. Rollout State for Rollback: Immediately General Availability (100%)
        rollout_record = RolloutStateRecord(
            release_id=rollback_record.id,
            channel=regressed_release.channel,
            stage=RolloutStage.GENERAL_AVAILABILITY.value,
            rollout_percentage=100.0,
            is_paused=False,
            total_targeted_clients=0,
            successful_installs=0,
            failed_installs=0,
            rollback_count=0,
            failure_rate=0.0,
            stage_updated_at=now,
        )
        session.add(rollout_record)
        await session.flush()

        return rollback_record
