package ai.cyberduel.mobile

import ai.cyberduel.mobile.domain.crypto.Ed25519Verifier
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import org.json.JSONObject

class Ed25519VerifierTest {

    private val publicKeyPem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAIVVxSe7/pHu3HANqpQRvKRloZVl62fJX6glvxPiX4uE=\n-----END PUBLIC KEY-----\n"

    private val canonicalJson = "{\"artifact_digest\":\"4356859d0e9111ce8c8bbeda426ab024008bcf0aa76f7ba0819c0bd01fa7347a\",\"artifact_size_bytes\":26,\"artifact_url\":\"/api/v1/updates/artifacts/4356859d0e9111ce8c8bbeda426ab024008bcf0aa76f7ba0819c0bd01fa7347a\",\"channel\":\"stable\",\"expires_at\":\"2028-12-31T23:59:59Z\",\"is_mandatory\":false,\"is_rollback\":false,\"max_client_version\":null,\"metadata\":{},\"min_client_version\":\"0.1.0\",\"min_engine_version\":\"1.0.0\",\"policy_version\":\"2026.10.5\",\"published_at\":\"2026-10-29T12:00:00Z\",\"publisher_key_id\":\"test-key-01\",\"release_id\":\"88888888-4444-4444-4444-121212121212\",\"release_notes\":\"Verified production release\",\"rollback_target_version\":null,\"sequence_number\":42,\"status\":\"published\",\"supported_platforms\":[\"browser_extension\",\"mobile_app\"]}"

    private val signatureHex = "fda8d430d379a305cb85a650c34d4392944fa9c77f46fefd863b881cabf52cc56ccf125e46d2ec2b611f6881fe73f81b78aa3d23b339343d156dc19b9a5d4901"

    @Test
    fun testValidEd25519Signature() {
        val valid = Ed25519Verifier.verifyDetachedSignature(
            publicKeyPem = publicKeyPem,
            data = canonicalJson.toByteArray(Charsets.UTF_8),
            signatureHex = signatureHex
        )
        assertTrue("Signature verification must succeed for valid vector", valid)
    }

    @Test
    fun testTamperedDataFailsSignature() {
        val tampered = canonicalJson.replace("2026.10.5", "2026.10.6")
        val valid = Ed25519Verifier.verifyDetachedSignature(
            publicKeyPem = publicKeyPem,
            data = tampered.toByteArray(Charsets.UTF_8),
            signatureHex = signatureHex
        )
        assertFalse("Tampered canonical payload must fail signature verification", valid)
    }

    @Test
    fun testCrossLanguageVectorFileIntegration() {
        val vectorFile = File("../../../datasets/test_vectors/cross_language_vectors.json")
        if (vectorFile.exists()) {
            val json = JSONObject(vectorFile.readText())
            val crypto = json.getJSONObject("crypto_vector")
            val pubPem = crypto.getString("public_key_pem")
            val payload = crypto.getString("canonical_json_str")
            val sig = crypto.getString("signature_hex")

            val valid = Ed25519Verifier.verifyDetachedSignature(
                publicKeyPem = pubPem,
                data = payload.toByteArray(Charsets.UTF_8),
                signatureHex = sig
            )
            assertTrue("Cross-language vector from file must pass", valid)
        }
    }
}

