package ai.cyberduel.mobile.domain.crypto

import android.util.Base64
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

object Ed25519Verifier {

    /**
     * Parse raw 32-byte Ed25519 public key from SubjectPublicKeyInfo PEM string.
     */
    fun parsePublicKeyPem(pem: String): ByteArray {
        val clean = pem.lines()
            .filter { !it.startsWith("-----") && it.isNotBlank() }
            .joinToString("")
            .trim()

        val der = try {
            java.util.Base64.getDecoder().decode(clean)
        } catch (_: Exception) {
            android.util.Base64.decode(clean, android.util.Base64.DEFAULT)
        }

        return when {
            der.size == 32 -> der
            der.size == 44 -> der.copyOfRange(12, 44) // Standard RFC 8410 header is 12 bytes
            der.size > 32 -> der.copyOfRange(der.size - 32, der.size)
            else -> throw IllegalArgumentException("Invalid Ed25519 public key DER size: ${der.size} bytes")
        }
    }

    /**
     * Verify detached Ed25519 signature over binary data.
     */
    fun verifyDetachedSignature(
        publicKeyPem: String,
        data: ByteArray,
        signatureHex: String
    ): Boolean {
        return try {
            val rawPubKey = parsePublicKeyPem(publicKeyPem)
            val signatureBytes = DigestUtil.hexToBytes(signatureHex)
            if (signatureBytes.size != 64) {
                return false
            }

            val pubKeyParams = Ed25519PublicKeyParameters(rawPubKey, 0)
            val signer = Ed25519Signer()
            signer.init(false, pubKeyParams)
            signer.update(data, 0, data.size)
            signer.verifySignature(signatureBytes)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Verify release manifest digital signature.
     */
    fun verifyManifestSignature(
        manifestJsonStr: String,
        signatureHex: String,
        publicKeyPem: String
    ): Boolean {
        val payloadBytes = CanonicalJson.getManifestSigningPayload(manifestJsonStr)
        return verifyDetachedSignature(publicKeyPem, payloadBytes, signatureHex)
    }
}

