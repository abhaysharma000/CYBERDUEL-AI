package ai.cyberduel.mobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ReleaseManifest(
    @SerialName("release_id") val releaseId: String,
    @SerialName("policy_version") val policyVersion: String,
    @SerialName("sequence_number") val sequenceNumber: Long,
    @SerialName("channel") val channel: ReleaseChannel = ReleaseChannel.STABLE,
    @SerialName("status") val status: ReleaseStatus = ReleaseStatus.PUBLISHED,
    @SerialName("published_at") val publishedAt: String,
    @SerialName("expires_at") val expiresAt: String,
    @SerialName("min_client_version") val minClientVersion: String = "0.1.0",
    @SerialName("max_client_version") val maxClientVersion: String? = null,
    @SerialName("min_engine_version") val minEngineVersion: String = "1.0.0",
    @SerialName("supported_platforms") val supportedPlatforms: List<String> = emptyList(),
    @SerialName("artifact_digest") val artifactDigest: String,
    @SerialName("artifact_size_bytes") val artifactSizeBytes: Long,
    @SerialName("artifact_url") val artifactUrl: String,
    @SerialName("publisher_key_id") val publisherKeyId: String,
    @SerialName("signature") val signature: String,
    @SerialName("is_mandatory") val isMandatory: Boolean = false,
    @SerialName("is_rollback") val isRollback: Boolean = false,
    @SerialName("rollback_target_version") val rollbackTargetVersion: String? = null,
    @SerialName("release_notes") val releaseNotes: String = "",
    @SerialName("metadata") val metadata: Map<String, String> = emptyMap()
)

@Serializable
data class SigningKeyMetadata(
    @SerialName("key_id") val keyId: String,
    @SerialName("algorithm") val algorithm: String = "ed25519",
    @SerialName("public_key_pem") val publicKeyPem: String,
    @SerialName("status") val status: KeyStatus,
    @SerialName("valid_from") val validFrom: String,
    @SerialName("valid_until") val validUntil: String? = null,
    @SerialName("revoked_at") val revokedAt: String? = null,
    @SerialName("revocation_reason") val revocationReason: String? = null
)

@Serializable
data class TrustAnchorSet(
    @SerialName("active_keys") val activeKeys: List<SigningKeyMetadata> = emptyList(),
    @SerialName("revoked_keys") val revokedKeys: List<SigningKeyMetadata> = emptyList(),
    @SerialName("timestamp") val timestamp: String
)

@Serializable
data class UpdateCheckRequest(
    @SerialName("client_id") val clientId: String,
    @SerialName("client_type") val clientType: String = "mobile_app",
    @SerialName("engine_version") val engineVersion: String = "1.0.0",
    @SerialName("current_policy_version") val currentPolicyVersion: String,
    @SerialName("current_sequence_number") val currentSequenceNumber: Long,
    @SerialName("channel") val channel: ReleaseChannel = ReleaseChannel.STABLE,
    @SerialName("platform") val platform: String = "Android-15"
)

@Serializable
data class UpdateCheckResponse(
    @SerialName("update_available") val updateAvailable: Boolean,
    @SerialName("latest_version") val latestVersion: String? = null,
    @SerialName("latest_sequence_number") val latestSequenceNumber: Long? = null,
    @SerialName("manifest_url") val manifestUrl: String? = null,
    @SerialName("is_mandatory") val isMandatory: Boolean = false,
    @SerialName("is_rollback") val isRollback: Boolean = false,
    @SerialName("rollback_target_version") val rollbackTargetVersion: String? = null,
    @SerialName("checked_at") val checkedAt: String,
    @SerialName("release_notes") val releaseNotes: String? = null
)

@Serializable
data class UpdateAcknowledgement(
    @SerialName("acknowledgement_id") val acknowledgementId: String,
    @SerialName("client_id") val clientId: String,
    @SerialName("release_id") val releaseId: String,
    @SerialName("policy_version") val policyVersion: String,
    @SerialName("sequence_number") val sequenceNumber: Long,
    @SerialName("status") val status: String, // 'installed' | 'failed' | 'rolled_back'
    @SerialName("error_message") val errorMessage: String? = null,
    @SerialName("is_rollback_applied") val isRollbackApplied: Boolean = false,
    @SerialName("channel") val channel: ReleaseChannel,
    @SerialName("reported_at") val reportedAt: String
)

