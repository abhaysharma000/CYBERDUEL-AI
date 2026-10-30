package ai.cyberduel.mobile

import ai.cyberduel.mobile.data.model.KeyStatus
import ai.cyberduel.mobile.data.model.PolicyBundle
import ai.cyberduel.mobile.data.model.ReleaseChannel
import ai.cyberduel.mobile.data.model.ReleaseManifest
import ai.cyberduel.mobile.data.model.ReleaseStatus
import ai.cyberduel.mobile.data.model.SigningKeyMetadata
import ai.cyberduel.mobile.data.model.TrustAnchorSet
import ai.cyberduel.mobile.domain.crypto.ClientUpdateVerifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.nio.charset.StandardCharsets

class ClientUpdateVerifierTest {

    private val pubKeyPem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAIVVxSe7/pHu3HANqpQRvKRloZVl62fJX6glvxPiX4uE=\n-----END PUBLIC KEY-----\n"
    private val sigHex = "fda8d430d379a305cb85a650c34d4392944fa9c77f46fefd863b881cabf52cc56ccf125e46d2ec2b611f6881fe73f81b78aa3d23b339343d156dc19b9a5d4901"
    private val artifactContent = "test policy bundle content"
    private val artifactBytes = artifactContent.toByteArray(StandardCharsets.UTF_8)
    private val artifactDigest = "4356859d0e9111ce8c8bbeda426ab024008bcf0aa76f7ba0819c0bd01fa7347a"

    private lateinit var validManifest: ReleaseManifest
    private lateinit var validManifestRawJson: String
    private lateinit var trustAnchors: TrustAnchorSet
    private lateinit var dummyBundle: PolicyBundle

    @Before
    fun setUp() {
        validManifest = ReleaseManifest(
            releaseId = "88888888-4444-4444-4444-121212121212",
            policyVersion = "2026.10.5",
            sequenceNumber = 42L,
            channel = ReleaseChannel.STABLE,
            status = ReleaseStatus.PUBLISHED,
            publishedAt = "2026-10-29T12:00:00Z",
            expiresAt = "2028-12-31T23:59:59Z",
            minClientVersion = "0.1.0",
            maxClientVersion = null,
            minEngineVersion = "1.0.0",
            supportedPlatforms = listOf("browser_extension", "mobile_app"),
            artifactDigest = artifactDigest,
            artifactSizeBytes = 26L,
            artifactUrl = "/api/v1/updates/artifacts/$artifactDigest",
            publisherKeyId = "test-key-01",
            isMandatory = false,
            isRollback = false,
            rollbackTargetVersion = null,
            releaseNotes = "Verified production release",
            metadata = emptyMap(),
            signature = sigHex
        )

        validManifestRawJson = """
            {
              "release_id": "88888888-4444-4444-4444-121212121212",
              "policy_version": "2026.10.5",
              "sequence_number": 42,
              "channel": "stable",
              "status": "published",
              "published_at": "2026-10-29T12:00:00Z",
              "expires_at": "2028-12-31T23:59:59Z",
              "min_client_version": "0.1.0",
              "max_client_version": null,
              "min_engine_version": "1.0.0",
              "supported_platforms": [
                "browser_extension",
                "mobile_app"
              ],
              "artifact_digest": "4356859d0e9111ce8c8bbeda426ab024008bcf0aa76f7ba0819c0bd01fa7347a",
              "artifact_size_bytes": 26,
              "artifact_url": "/api/v1/updates/artifacts/4356859d0e9111ce8c8bbeda426ab024008bcf0aa76f7ba0819c0bd01fa7347a",
              "publisher_key_id": "test-key-01",
              "is_mandatory": false,
              "is_rollback": false,
              "rollback_target_version": null,
              "release_notes": "Verified production release",
              "metadata": {},
              "signature": "$sigHex"
            }
        """.trimIndent()

        trustAnchors = TrustAnchorSet(
            activeKeys = listOf(
                SigningKeyMetadata(
                    keyId = "test-key-01",
                    algorithm = "ed25519",
                    publicKeyPem = pubKeyPem,
                    status = KeyStatus.ACTIVE,
                    validFrom = "2026-01-01T00:00:00Z",
                    validUntil = "2029-01-01T00:00:00Z"
                )
            ),
            revokedKeys = emptyList(),
            timestamp = "2026-10-01T00:00:00Z"
        )

        dummyBundle = PolicyBundle(
            bundleId = "test-bundle-id",
            policyVersion = "2026.10.5",
            sequenceNumber = 42L,
            createdAt = "2026-10-29T12:00:00Z",
            expiresAt = "2028-12-31T23:59:59Z"
        )
    }

    @Test
    fun testValidUpdatePassesAllSevenSteps() {
        val verifier = ClientUpdateVerifier(
            currentSequence = 10L,
            currentPolicyVersion = "2026.10.1",
            clientVersion = "1.0.0",
            engineVersion = "1.0.0"
        )

        val result = verifier.verify(
            manifest = validManifest,
            manifestRawJson = validManifestRawJson,
            artifactRawBytes = artifactBytes,
            bundle = dummyBundle,
            trustAnchors = trustAnchors
        )

        assertTrue(result.errorMessage ?: "", result.isValid)
        assertEquals(7, result.checkpointsPassed.size)
    }

    @Test
    fun testStep1UnknownKeyFails() {
        val verifier = ClientUpdateVerifier(currentSequence = 10L)
        val emptyAnchors = TrustAnchorSet(activeKeys = emptyList(), revokedKeys = emptyList(), timestamp = "2026-01-01T00:00:00Z")

        val result = verifier.verify(
            manifest = validManifest,
            manifestRawJson = validManifestRawJson,
            artifactRawBytes = artifactBytes,
            bundle = dummyBundle,
            trustAnchors = emptyAnchors
        )

        assertFalse(result.isValid)
        assertEquals("Step 1: Trust Anchor Verification", result.stepFailed)
    }

    @Test
    fun testStep1RevokedKeyFails() {
        val verifier = ClientUpdateVerifier(currentSequence = 10L)
        val revokedAnchors = trustAnchors.copy(
            revokedKeys = listOf(
                SigningKeyMetadata(
                    keyId = "test-key-01",
                    algorithm = "ed25519",
                    publicKeyPem = pubKeyPem,
                    status = KeyStatus.REVOKED,
                    validFrom = "2026-01-01T00:00:00Z",
                    validUntil = "2029-01-01T00:00:00Z"
                )
            )
        )

        val result = verifier.verify(
            manifest = validManifest,
            manifestRawJson = validManifestRawJson,
            artifactRawBytes = artifactBytes,
            bundle = dummyBundle,
            trustAnchors = revokedAnchors
        )

        assertFalse(result.isValid)
        assertEquals("Step 1: Trust Anchor Verification", result.stepFailed)
    }

    @Test
    fun testStep2CorruptedSignatureFails() {
        val verifier = ClientUpdateVerifier(currentSequence = 10L)
        val corruptedSig = validManifest.signature.replace('a', 'b')
        val corruptedManifest = validManifest.copy(signature = corruptedSig)
        val corruptedJson = validManifestRawJson.replace(validManifest.signature, corruptedSig)

        val result = verifier.verify(
            manifest = corruptedManifest,
            manifestRawJson = corruptedJson,
            artifactRawBytes = artifactBytes,
            bundle = dummyBundle,
            trustAnchors = trustAnchors
        )

        assertFalse(result.isValid)
        assertEquals("Step 2: Digital Signature Verification", result.stepFailed)
    }

    @Test
    fun testStep3SequenceAntiReplayFails() {
        // Current sequence is 50, but update has 42 -> replay attack
        val verifier = ClientUpdateVerifier(currentSequence = 50L)

        val result = verifier.verify(
            manifest = validManifest,
            manifestRawJson = validManifestRawJson,
            artifactRawBytes = artifactBytes,
            bundle = dummyBundle,
            trustAnchors = trustAnchors
        )

        assertFalse(result.isValid)
        assertEquals("Step 3: Anti-Replay Sequence Ordering", result.stepFailed)
    }

    @Test
    fun testStep4IncompatiblePlatformFails() {
        val verifier = ClientUpdateVerifier(currentSequence = 10L)
        val badPlatformManifest = validManifest.copy(supportedPlatforms = listOf("server_only"))

        val result = verifier.verify(
            manifest = badPlatformManifest,
            manifestRawJson = validManifestRawJson,
            artifactRawBytes = artifactBytes,
            bundle = dummyBundle,
            trustAnchors = trustAnchors
        )

        assertFalse(result.isValid)
        assertEquals("Step 4: Platform Compatibility", result.stepFailed)
    }

    @Test
    fun testStep6ArtifactDigestMismatchFails() {
        val verifier = ClientUpdateVerifier(currentSequence = 10L)
        val tamperedArtifactBytes = "tampered bytes".toByteArray(StandardCharsets.UTF_8)

        val result = verifier.verify(
            manifest = validManifest,
            manifestRawJson = validManifestRawJson,
            artifactRawBytes = tamperedArtifactBytes,
            bundle = dummyBundle,
            trustAnchors = trustAnchors
        )

        assertFalse(result.isValid)
        assertEquals("Step 6: Artifact Integrity", result.stepFailed)
    }
}

