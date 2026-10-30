package ai.cyberduel.mobile

import ai.cyberduel.mobile.domain.crypto.CanonicalJson
import org.junit.Assert.assertEquals
import org.junit.Test

class CanonicalJsonTest {

    @Test
    fun testCanonicalKeyOrdering() {
        val input = """{"z": 1, "a": "hello", "m": [3, 2, 1], "c": {"b": 2, "a": 1}}"""
        val expected = """{"a":"hello","c":{"a":1,"b":2},"m":[3,2,1],"z":1}"""
        val actual = CanonicalJson.canonicalizeToString(input)
        assertEquals(expected, actual)
    }

    @Test
    fun testManifestSigningPayloadExcludesSignature() {
        val manifestJson = """
            {
                "release_id": "test-123",
                "sequence_number": 5,
                "signature": "abcdef123456",
                "policy_version": "2026.10.1"
            }
        """.trimIndent()

        val payload = CanonicalJson.getManifestSigningPayloadString(manifestJson)
        val expected = """{"policy_version":"2026.10.1","release_id":"test-123","sequence_number":5}"""
        assertEquals(expected, payload)
    }
}

