package ai.cyberduel.mobile

import ai.cyberduel.mobile.domain.crypto.DigestUtil
import org.junit.Assert.assertEquals
import org.junit.Test

class DigestUtilTest {

    @Test
    fun testSha256Digest() {
        val input = "hello world"
        val expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        val actual = DigestUtil.sha256Hex(input)
        assertEquals(expected, actual)
    }

    @Test
    fun testEmptySha256() {
        val expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        val actual = DigestUtil.sha256Hex("")
        assertEquals(expected, actual)
    }
}

