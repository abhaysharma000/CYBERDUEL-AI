"""Enforces explicit administrative release authorization policy and records deployment audit trail."""

from datetime import UTC, datetime
from uuid import UUID

from cyberduel_contracts.enums import (
    ReleaseChannel,
    ReleaseStatus,
    RolloutStage,
)
from cyberduel_contracts.releases import ReleaseAuthorization
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.releases import (
    ReleaseAuthorizationRecord,
    ReleaseRecord,
    RolloutStateRecord,
)
from apps.api.app.services.releases.bundle_builder import PolicyBundleBuilder
from apps.api.app.services.releases.eligibility import ReleaseEligibilityService
from apps.api.app.services.releases.key_manager import SigningKeyManager
from apps.api.app.services.releases.manifest_builder import ReleaseManifestBuilder
from apps.api.app.services.releases.storage import ArtifactStorageService


class ReleaseApprovalError(Exception):
    """Raised when an ineligible candidate is submitted for release or authorization violates policy."""


class ReleaseApprovalService:
    """Manages the explicit authorization step required to transition an evaluated defense to production release."""

    def __init__(
        self,
        eligibility_service: ReleaseEligibilityService | None = None,
        bundle_builder: PolicyBundleBuilder | None = None,
        manifest_builder: ReleaseManifestBuilder | None = None,
        storage_service: ArtifactStorageService | None = None,
        key_manager: SigningKeyManager | None = None,
    ) -> None:
        self.eligibility_service = eligibility_service or ReleaseEligibilityService()
        self.bundle_builder = bundle_builder or PolicyBundleBuilder()
        self.key_manager = key_manager or SigningKeyManager()
        from apps.api.app.services.releases.signing import ReleaseSigningService

        signing_svc = ReleaseSigningService(key_manager=self.key_manager)
        self.manifest_builder = manifest_builder or ReleaseManifestBuilder(
            signing_service=signing_svc
        )
        self.storage_service = storage_service or ArtifactStorageService()

    async def authorize_and_stage_release(
        self,
        session: AsyncSession,
        candidate_id: UUID,
        evaluation_report_id: UUID,
        policy_version: str,
        target_channel: ReleaseChannel,
        authorized_by: str,
        rationale: str,
        rule_spec: dict,
        threat_indicators: list[dict] | None = None,
        scoring_thresholds: dict[str, float] | None = None,
        min_client_version: str = "0.1.0",
        min_engine_version: str = "1.0.0",
        supported_platforms: list[str] | None = None,
        release_notes: str = "",
    ) -> tuple[ReleaseRecord, ReleaseAuthorization]:
        """Authorize an evaluated candidate and produce a signed, staged release ready for rollout."""
        # 1. Verify Eligibility
        eligibility = await self.eligibility_service.check_eligibility(
            session=session,
            candidate_id=candidate_id,
            evaluation_report_id=evaluation_report_id,
        )
        if not eligibility.is_eligible:
            reasons_str = "; ".join(eligibility.reasons)
            raise ReleaseApprovalError(
                f"Candidate {candidate_id} cannot be authorized for release: {reasons_str}"
            )

        # 2. Check if policy_version already exists
        check_stmt = select(ReleaseRecord).where(ReleaseRecord.policy_version == policy_version)
        existing = (await session.execute(check_stmt)).scalar_one_or_none()
        if existing:
            raise ReleaseApprovalError(f"Policy release version '{policy_version}' already exists")

        # 3. Retrieve or create Active Signing Key
        signing_key_record = await self.key_manager.get_active_key(session)
        publisher_key_id = signing_key_record.key_id

        # 4. Allocate Monotonic Sequence Number
        sequence_number = await self.manifest_builder.get_next_sequence_number(session)

        # 5. Compile and Validate Declarative Policy Bundle
        bundle, bundle_bytes, artifact_digest = self.bundle_builder.build_bundle(
            policy_version=policy_version,
            sequence_number=sequence_number,
            rule_spec=rule_spec,
            threat_indicators=threat_indicators,
            scoring_thresholds=scoring_thresholds,
            metadata={"authorized_by": authorized_by, "channel": target_channel.value},
        )

        # 6. Store Artifact Immutably
        filename_hint = f"policy-{policy_version}-{artifact_digest[:12]}.json"
        saved_path, _ = self.storage_service.store_artifact(
            artifact_bytes=bundle_bytes,
            expected_digest=artifact_digest,
            filename_hint=filename_hint,
        )
        artifact_url = f"/api/v1/updates/artifacts/{artifact_digest}"

        # 7. Build and Sign Release Manifest
        manifest = await self.manifest_builder.build_signed_manifest(
            session=session,
            policy_version=policy_version,
            artifact_digest=artifact_digest,
            artifact_size_bytes=len(bundle_bytes),
            artifact_url=artifact_url,
            publisher_key_id=publisher_key_id,
            channel=target_channel,
            status=ReleaseStatus.APPROVED,
            min_client_version=min_client_version,
            min_engine_version=min_engine_version,
            supported_platforms=supported_platforms,
            expires_at=bundle.expires_at,
            is_mandatory=False,
            is_rollback=False,
            release_notes=release_notes,
            sequence_number=sequence_number,
            metadata={"evaluation_report_id": str(evaluation_report_id)},
        )

        # 8. Persist Release Record
        release_record = ReleaseRecord(
            policy_version=policy_version,
            sequence_number=sequence_number,
            channel=target_channel.value,
            candidate_id=candidate_id,
            evaluation_report_id=evaluation_report_id,
            status=ReleaseStatus.APPROVED.value,
            min_client_version=min_client_version,
            max_client_version=None,
            min_engine_version=min_engine_version,
            supported_platforms=manifest.supported_platforms,
            artifact_path=str(saved_path),
            artifact_digest=artifact_digest,
            artifact_size_bytes=len(bundle_bytes),
            publisher_key_id=publisher_key_id,
            signature=manifest.signature,
            manifest_payload=manifest.model_dump(mode="json"),
            bundle_payload=bundle.model_dump(mode="json"),
            published_at=None,
            expires_at=bundle.expires_at,
            is_mandatory=False,
            is_rollback=False,
            rollback_target_version=None,
            release_notes=release_notes,
        )
        session.add(release_record)
        await session.flush()

        # 9. Persist Authorization Record
        now = datetime.now(UTC)
        auth_record = ReleaseAuthorizationRecord(
            release_id=release_record.id,
            candidate_id=candidate_id,
            evaluation_report_id=evaluation_report_id,
            policy_version=policy_version,
            target_channel=target_channel.value,
            authorized_by=authorized_by,
            rationale=rationale,
            authorized_at=now,
        )
        session.add(auth_record)

        # 10. Initialize Rollout State
        rollout_record = RolloutStateRecord(
            release_id=release_record.id,
            channel=target_channel.value,
            stage=RolloutStage.INTERNAL.value,
            rollout_percentage=0.0,
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

        auth_contract = ReleaseAuthorization(
            authorization_id=auth_record.id,
            release_id=release_record.id,
            candidate_id=candidate_id,
            evaluation_report_id=evaluation_report_id,
            policy_version=policy_version,
            target_channel=target_channel,
            authorized_by=authorized_by,
            rationale=rationale,
            authorized_at=now,
        )

        return release_record, auth_contract
