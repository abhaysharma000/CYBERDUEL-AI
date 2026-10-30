package ai.cyberduel.mobile.domain.crypto

import java.security.MessageDigest

object DigestUtil {

    fun sha256Hex(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(data)
        return bytesToHex(hashBytes)
    }

    fun sha256Hex(text: String): String {
        return sha256Hex(text.toByteArray(Charsets.UTF_8))
    }

    fun canonicalSha256(jsonStr: String): String {
        val canonBytes = CanonicalJson.canonicalize(jsonStr)
        return sha256Hex(canonBytes)
    }

    fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim().removePrefix("0x").removePrefix("0X")
        require(clean.length % 2 == 0) { "Invalid hex string length: ${clean.length}" }
        val bytes = ByteArray(clean.length / 2)
        for (i in clean.indices step 2) {
            bytes[i / 2] = clean.substring(i, i + 2).toInt(16).toByte()
        }
        return bytes
    }

    fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(String.format("%02x", b.toInt() and 0xFF))
        }
        return sb.toString()
    }
}

