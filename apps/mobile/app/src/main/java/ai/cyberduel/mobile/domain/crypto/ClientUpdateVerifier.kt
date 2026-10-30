package ai.cyberduel.mobile.domain.crypto

import ai.cyberduel.mobile.data.model.PolicyBundle
import ai.cyberduel.mobile.data.model.ReleaseManifest
import ai.cyberduel.mobile.data.model.TrustAnchorSet
import java.time.Instant
import java.time.format.DateTimeParseException

data class VerificationResult(
    val isValid: Boolean,
    val stepFailed: String? = null,
    val errorMessage: String? = null,
    val checkpointsPassed: List<String> = emptyList()
)

class ClientUpdateVerifier(
    private val currentSequence: Long = 0,
    private val currentPolicyVersion: String = "0.0.0",
    private val clientVersion: String = "1.0.0",
    private val engineVersion: String = "1.0.0"
) {

    private val allowedOperators = setOf(
        "eq", "ne", "gt", "gte", "lt", "lte", "contains", "in", "matches_regex"
    )

    fun verify(
        manifest: ReleaseManifest,
        manifestRawJson: String,
        artifactRawBytes: ByteArray,
        bundle: PolicyBundle,
        trustAnchors: TrustAnchorSet
    ): VerificationResult {
        val passed = mutableListOf<String>()

        // Step 1: Trust Anchor & Key Status Verification
        val activeKey = trustAnchors.activeKeys.firstOrNull {
            it.keyId == manifest.publisherKeyId && it.status.name.equals("active", ignoreCase = true)
        }
        if (activeKey == null) {
            return VerificationResult(
                isValid = false,
                stepFailed = "Step 1: Trust Anchor Verification",
                errorMessage = "Publisher key '${manifest.publisherKeyId}' is not in active trust anchors.",
                checkpointsPassed = passed
            )
        }

        val isRevoked = trustAnchors.revokedKeys.any { it.keyId == manifest.publisherKeyId }
        if (isRevoked) {
            return VerificationResult(
                isValid = false,
                stepFailed = "Step 1: Trust Anchor Verification",
                errorMessage = "Publisher key '${manifest.publisherKeyId}' has been revoked.",
                checkpointsPassed = passed
            )
        }
        passed.add("Step 1: Trust Anchor Verification")

        // Step 2: Digital Signature Verification
        val signatureValid = Ed25519Verifier.verifyManifestSignature(
            manifestJsonStr = manifestRawJson,
            signatureHex = manifest.signature,
            publicKeyPem = activeKey.publicKeyPem
        )
        if (!signatureValid) {
            return VerificationResult(
                isValid = false,
                stepFailed = "Step 2: Digital Signature Verification",
                errorMessage = "Ed25519 digital signature verification failed over canonical manifest.",
                checkpointsPassed = passed
            )
        }
        passed.add("Step 2: Digital Signature Verification")

        // Step 3: Anti-Replay Monotonic Sequence Ordering
        if (manifest.sequenceNumber <= currentSequence) {
            return VerificationResult(
                isValid = false,
                stepFailed = "Step 3: Anti-Replay Sequence Ordering",
                errorMessage = "Sequence ${manifest.sequenceNumber} must be strictly greater than current $currentSequence.",
                checkpointsPassed = passed
            )
        }
        passed.add("Step 3: Anti-Replay Sequence Ordering")

        // Step 4: Client & Platform Version Compatibility
        val isPlatformSupported = manifest.supportedPlatforms.isEmpty() ||
                manifest.supportedPlatforms.any { it.equals("mobile_app", ignoreCase = true) || it.equals("android", ignoreCase = true) || it.equals("all", ignoreCase = true) }
        if (!isPlatformSupported) {
            return VerificationResult(
                isValid = false,
                stepFailed = "Step 4: Platform Compatibility",
                errorMessage = "Release manifest does not support 'mobile_app' or 'android' platform.",
                checkpointsPassed = passed
            )
        }

        if (compareSemver(clientVersion, manifest.minClientVersion) < 0) {
            return VerificationResult(
                isValid = false,
                stepFailed = "Step 4: Version Compatibility",
                errorMessage = "Client version $clientVersion is below minimum required ${manifest.minClientVersion}.",
                checkpointsPassed = passed
            )
        }

        if (compareSemver(engineVersion, manifest.minEngineVersion) < 0) {
            return VerificationResult(
                isValid = false,
                stepFailed = "Step 4: Version Compatibility",
                errorMessage = "Engine version $engineVersion is below minimum required ${manifest.minEngineVersion}.",
                checkpointsPassed = passed
            )
        }
        passed.add("Step 4: Version Compatibility")

        // Step 5: Expiration Cutoff Check
        try {
            val expiresAt = Instant.parse(manifest.expiresAt)
            if (Instant.now().isAfter(expiresAt)) {
                return VerificationResult(
                    isValid = false,
                    stepFailed = "Step 5: Expiration Check",
                    errorMessage = "Release manifest expired at ${manifest.expiresAt}.",
                    checkpointsPassed = passed
                )
            }
        } catch (_: DateTimeParseException) {
            return VerificationResult(
                isValid = false,
                stepFailed = "Step 5: Expiration Check",
                errorMessage = "Invalid expires_at timestamp format in manifest: ${manifest.expiresAt}.",
                checkpointsPassed = passed
            )
        }
        passed.add("Step 5: Expiration Check")

        // Step 6: Artifact Digest Verification
        val computedDigest = DigestUtil.sha256Hex(artifactRawBytes)
        if (!computedDigest.equals(manifest.artifactDigest, ignoreCase = true)) {
            return VerificationResult(
                isValid = false,
                stepFailed = "Step 6: Artifact Integrity",
                errorMessage = "Artifact digest mismatch. Expected ${manifest.artifactDigest}, computed $computedDigest.",
                checkpointsPassed = passed
            )
        }
        passed.add("Step 6: Artifact Integrity")

        // Step 7: Bundle Schema and Declarative AST Safety
        val safetyResult = verifyBundleSafety(bundle)
        if (!safetyResult.first) {
            return VerificationResult(
                isValid = false,
                stepFailed = "Step 7: Bundle Safety Check",
                errorMessage = safetyResult.second,
                checkpointsPassed = passed
            )
        }
        passed.add("Step 7: Bundle Safety Check")

        return VerificationResult(
            isValid = true,
            checkpointsPassed = passed
        )
    }

    private fun verifyBundleSafety(bundle: PolicyBundle): Pair<Boolean, String?> {
        if (bundle.policyVersion.isBlank() || bundle.sequenceNumber <= 0) {
            return Pair(false, "Malformed policy bundle: missing version or sequence number.")
        }

        for (rule in bundle.rules) {
            if (rule.predicates.isEmpty()) {
                return Pair(false, "Rule '${rule.ruleId}' has no predicates.")
            }
            if (rule.predicates.size > 10) {
                return Pair(false, "Rule '${rule.ruleId}' exceeds maximum predicate limit of 10.")
            }

            for (pred in rule.predicates) {
                if (!allowedOperators.contains(pred.operator)) {
                    return Pair(false, "Rule '${rule.ruleId}' uses forbidden operator '${pred.operator}'.")
                }
                if (pred.operator == "matches_regex") {
                    val pattern = pred.value.toString().removeSurrounding("\"")
                    if (pattern.length > 128) {
                        return Pair(false, "Regex in rule '${rule.ruleId}' exceeds 128 characters.")
                    }
                    try {
                        Regex(pattern)
                    } catch (e: Exception) {
                        return Pair(false, "Invalid regex pattern in rule '${rule.ruleId}': ${e.message}")
                    }
                }
            }
        }
        return Pair(true, null)
    }

    private fun compareSemver(v1: String, v2: String): Int {
        val p1 = v1.split('.').map { it.toIntOrNull() ?: 0 }
        val p2 = v2.split('.').map { it.toIntOrNull() ?: 0 }
        val maxLen = maxOf(p1.size, p2.size)
        for (i in 0 until maxLen) {
            val a = p1.getOrElse(i) { 0 }
            val b = p2.getOrElse(i) { 0 }
            if (a > b) return 1
            if (a < b) return -1
        }
        return 0
    }
}

