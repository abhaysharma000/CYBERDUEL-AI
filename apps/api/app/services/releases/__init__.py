"""Release management, cryptographic signing, staged rollout, and client update services."""

from apps.api.app.services.releases.acknowledgement import ClientAcknowledgementService
from apps.api.app.services.releases.approval import (
    ReleaseApprovalError,
    ReleaseApprovalService,
)
from apps.api.app.services.releases.bundle_builder import (
    PolicyBundleBuilder,
    PolicyBundleValidationError,
)
from apps.api.app.services.releases.distribution import UpdateDistributionService
from apps.api.app.services.releases.eligibility import ReleaseEligibilityService
from apps.api.app.services.releases.key_manager import SigningKeyManager
from apps.api.app.services.releases.manifest_builder import ReleaseManifestBuilder
from apps.api.app.services.releases.rollback import RollbackError, RollbackService
from apps.api.app.services.releases.rollout import RolloutManager
from apps.api.app.services.releases.signing import ReleaseSigningService
from apps.api.app.services.releases.storage import (
    ArtifactStorageError,
    ArtifactStorageService,
)
from apps.api.app.services.releases.verifier import (
    ClientUpdateVerifier,
    VerificationResult,
)

__all__ = [
    "ArtifactStorageError",
    "ArtifactStorageService",
    "ClientAcknowledgementService",
    "ClientUpdateVerifier",
    "PolicyBundleBuilder",
    "PolicyBundleValidationError",
    "ReleaseApprovalError",
    "ReleaseApprovalService",
    "ReleaseEligibilityService",
    "ReleaseManifestBuilder",
    "ReleaseSigningService",
    "RollbackError",
    "RollbackService",
    "RolloutManager",
    "SigningKeyManager",
    "UpdateDistributionService",
    "VerificationResult",
]
