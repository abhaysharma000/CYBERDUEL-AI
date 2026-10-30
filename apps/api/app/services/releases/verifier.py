"""Client-side verification reference implementation for PC Browser Extension and Mobile Companion App."""

import json
from datetime import UTC, datetime
from typing import Any

from cyberduel_contracts.crypto import compute_sha256, verify_manifest
from cyberduel_contracts.releases import (
    LocalProtectionPolicyBundle,
    ReleaseManifest,
    TrustAnchorSet,
)
from pydantic import BaseModel


class VerificationResult(BaseModel):
    """Structured report returned from client-side verification of an update manifest and bundle."""

    is_valid: bool
    error: str | None = None
    step_passed: str | None = None
    bundle: LocalProtectionPolicyBundle | None = None


class ClientUpdateVerifier:
    """Rigorous client-side cryptographic and compatibility verifier.

    Protects edge clients from malicious updates, tampered artifacts, replay attacks,
    and incompatible policy definitions.
    """

    @classmethod
    def verify_update(
        cls,
        manifest: ReleaseManifest | dict[str, Any],
        bundle_bytes: bytes,
        trust_anchors: TrustAnchorSet,
        client_version: str,
        engine_version: str,
        client_platform: str,
        current_sequence_number: int = 0,
        now: datetime | None = None,
    ) -> VerificationResult:
        """Execute complete 7-step cryptographic and integrity verification."""
        current_time = now or datetime.now(UTC)

        if isinstance(manifest, dict):
            try:
                manifest_model = ReleaseManifest.model_validate(manifest)
            except Exception as e:
                return VerificationResult(is_valid=False, error=f"Invalid manifest schema: {e}")
            manifest_dict = manifest
        else:
            manifest_model = manifest
            manifest_dict = manifest.model_dump(mode="json")

        # Step 1: Trust Anchor Verification
        revoked_ids = {k.key_id for k in trust_anchors.revoked_keys}
        if manifest_model.publisher_key_id in revoked_ids:
            return VerificationResult(
                is_valid=False,
                error=f"Signing key '{manifest_model.publisher_key_id}' has been revoked",
            )

        active_keys = {k.key_id: k for k in trust_anchors.active_keys}
        if manifest_model.publisher_key_id not in active_keys:
            return VerificationResult(
                is_valid=False,
                error=f"Signing key '{manifest_model.publisher_key_id}' is not in active trust anchors",
            )

        signing_key_meta = active_keys[manifest_model.publisher_key_id]

        # Step 2: Digital Signature Verification
        is_sig_valid = verify_manifest(
            manifest_data=manifest_dict,
            signature_hex=manifest_model.signature,
            public_key_pem=signing_key_meta.public_key_pem,
        )
        if not is_sig_valid:
            return VerificationResult(
                is_valid=False,
                error="Cryptographic signature verification failed: manifest has been tampered or signature is invalid",
            )

        # Step 3: Anti-Replay and Monotonic Sequence Check
        if manifest_model.sequence_number <= current_sequence_number:
            return VerificationResult(
                is_valid=False,
                error=(
                    f"Replay detected: manifest sequence ({manifest_model.sequence_number}) "
                    f"is not strictly greater than client current sequence ({current_sequence_number})"
                ),
            )

        # Step 4: Freshness / Expiration Check
        if manifest_model.expires_at <= current_time:
            return VerificationResult(
                is_valid=False,
                error=f"Update manifest expired at {manifest_model.expires_at.isoformat()} (current: {current_time.isoformat()})",
            )

        # Step 5: Compatibility Constraints Check
        if (
            manifest_model.supported_platforms
            and client_platform not in manifest_model.supported_platforms
        ):
            return VerificationResult(
                is_valid=False,
                error=(
                    f"Platform '{client_platform}' not supported by release "
                    f"(supported: {manifest_model.supported_platforms})"
                ),
            )

        # Step 6: Artifact Integrity (SHA-256) Check
        computed_digest = compute_sha256(bundle_bytes)
        if computed_digest.lower() != manifest_model.artifact_digest.lower():
            return VerificationResult(
                is_valid=False,
                error=(
                    f"Artifact digest mismatch: received bytes hash to {computed_digest}, "
                    f"expected {manifest_model.artifact_digest}"
                ),
            )

        # Step 7: Bundle Schema and Semantic Match Check
        try:
            bundle_raw = json.loads(bundle_bytes.decode("utf-8"))
            bundle_model = LocalProtectionPolicyBundle.model_validate(bundle_raw)
        except Exception as e:
            return VerificationResult(
                is_valid=False,
                error=f"Policy bundle payload failed declarative validation: {e}",
            )

        if bundle_model.policy_version != manifest_model.policy_version:
            return VerificationResult(
                is_valid=False,
                error=(
                    f"Version mismatch: bundle version '{bundle_model.policy_version}' "
                    f"does not match manifest version '{manifest_model.policy_version}'"
                ),
            )

        if bundle_model.sequence_number != manifest_model.sequence_number:
            return VerificationResult(
                is_valid=False,
                error=(
                    f"Sequence mismatch: bundle sequence ({bundle_model.sequence_number}) "
                    f"does not match manifest sequence ({manifest_model.sequence_number})"
                ),
            )

        return VerificationResult(
            is_valid=True,
            step_passed="all_checks_verified",
            bundle=bundle_model,
        )
