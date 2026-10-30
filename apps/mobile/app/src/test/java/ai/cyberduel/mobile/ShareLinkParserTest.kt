package ai.cyberduel.mobile

import ai.cyberduel.mobile.domain.sharing.ShareLinkParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ShareLinkParserTest {

    @Test
    fun testDirectUrlExtraction() {
        val input = "https://example.com/login?param=1"
        val urls = ShareLinkParser.extractUrls(input)
        assertEquals(1, urls.size)
        assertEquals("https://example.com/login?param=1", urls[0])
    }

    @Test
    fun testSentenceWithUrlAndPunctuation() {
        val input = "Hey, check out this phishing portal: https://evil-phish.net/account. Please verify!"
        val urls = ShareLinkParser.extractUrls(input)
        assertEquals(1, urls.size)
        assertEquals("https://evil-phish.net/account", urls[0])
    }

    @Test
    fun testWwwPrefixPrependHttps() {
        val input = "Visit www.example.org/resources for details."
        val urls = ShareLinkParser.extractUrls(input)
        assertEquals(1, urls.size)
        assertEquals("https://www.example.org/resources", urls[0])
    }

    @Test
    fun testUrlInParentheses() {
        val input = "Click here (https://safe-portal.com/auth) to continue."
        val urls = ShareLinkParser.extractUrls(input)
        assertEquals(1, urls.size)
        assertEquals("https://safe-portal.com/auth", urls[0])
    }

    @Test
    fun testNullOrEmptyInput() {
        assertTrue(ShareLinkParser.extractUrls(null).isEmpty())
        assertTrue(ShareLinkParser.extractUrls("").isEmpty())
        assertTrue(ShareLinkParser.extractUrls("Just some text with no links at all.").isEmpty())
    }

    @Test
    fun testMaxUrlsBounded() {
        val input = """
            https://link1.com
            https://link2.com
            https://link3.com
            https://link4.com
            https://link5.com
            https://link6.com
            https://link7.com
        """.trimIndent()

        val urls = ShareLinkParser.extractUrls(input)
        assertEquals(5, urls.size)
    }
}

