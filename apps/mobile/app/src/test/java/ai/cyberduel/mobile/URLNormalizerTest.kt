package ai.cyberduel.mobile

import ai.cyberduel.mobile.domain.engine.URLNormalizer
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class URLNormalizerTest {

    @Test
    fun testStandardNormalization() {
        val raw = "http://example.com/path?foo=bar#frag"
        val norm = URLNormalizer.normalize(raw)
        assertEquals("http", norm.scheme)
        assertEquals("example.com", norm.host)
        assertEquals("http://example.com/path?foo=bar", norm.canonicalUrl)
        assertEquals("example.com", norm.domain)
        assertEquals("011e811b83fb365ed990b53dd46867076cc82653d9bc9fd777198f04aba2c665", norm.urlSha256)
        assertEquals("a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947", norm.domainSha256)
        assertFalse(norm.hasEmbeddedCredentials)
        assertFalse(norm.isIpLiteral)
    }

    @Test
    fun testDefaultPortStripping() {
        val normHttps = URLNormalizer.normalize("https://example.com:443/test/")
        assertEquals("https://example.com/test/", normHttps.canonicalUrl)
        assertEquals("b97e293009b8694a60570a1fc7169293eb1fdfbd9584e97178ea5d93e8177aee", normHttps.urlSha256)

        val normHttp = URLNormalizer.normalize("http://example.com:80/")
        assertEquals("http://example.com/", normHttp.canonicalUrl)
        assertEquals("2a1b402420ef46577471cdc7409b0fa2c6a204db316e59ade2d805435489a067", normHttp.urlSha256)
    }

    @Test
    fun testNonDefaultPortRetained() {
        val norm = URLNormalizer.normalize("http://example.com:8080/api")
        assertEquals("http://example.com:8080/api", norm.canonicalUrl)
        assertEquals("ec216db4bdd49321ee6e8de32acefe73cc04162364bc61df830253fec0d0320e", norm.urlSha256)
    }

    @Test
    fun testUppercaseAndTrailingDot() {
        val norm = URLNormalizer.normalize("HTTPS://EXAMPLE.COM./")
        assertEquals("https://example.com/", norm.canonicalUrl)
        assertEquals("0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7", norm.urlSha256)
    }

    @Test
    fun testDotSegmentResolution() {
        val norm = URLNormalizer.normalize("https://example.com/a/b/../c/./d")
        assertEquals("https://example.com/a/c/d", norm.canonicalUrl)
        assertEquals("ed550e401b1cd8092fdfebd37be4921742e1daa5ca977ee7b7c40ed780abd163", norm.urlSha256)
    }

    @Test
    fun testSensitiveParamRedaction() {
        val norm = URLNormalizer.normalize("https://example.com/login?token=secret123&user=alice")
        assertEquals("https://example.com/login?token=%5BREDACTED%5D&user=alice", norm.canonicalUrl)
        assertEquals("a7a927031f4e51de66cb63e1dc784baf44ba86d5756f061298a9967ed78dc2be", norm.urlSha256)
    }

    @Test
    fun testEmbeddedCredentialsStripped() {
        val norm = URLNormalizer.normalize("https://alice:pass123@example.com/account")
        assertEquals("https://example.com/account", norm.canonicalUrl)
        assertTrue(norm.hasEmbeddedCredentials)
        assertEquals("alice:[REDACTED]", norm.userinfo)
        assertEquals("7df3842fae8f57b45c815f51f8e94b8bf5a2ef8bebbbfb9feba3fe388ec5deea", norm.urlSha256)
    }

    @Test
    fun testIpLiteral() {
        val norm = URLNormalizer.normalize("http://192.168.1.1:8000/admin")
        assertEquals("http://192.168.1.1:8000/admin", norm.canonicalUrl)
        assertTrue(norm.isIpLiteral)
        assertEquals("192.168.1.1", norm.domain)
        assertEquals("dd3f35832608ee50ff9a91a92f693e8e71c8da960f2b083211cc60542ac38271", norm.urlSha256)
    }

    @Test
    fun testCrossLanguageVectorsFromFile() {
        val possiblePaths = listOf(
            File("../../../datasets/test_vectors/cross_language_vectors.json"),
            File("../../datasets/test_vectors/cross_language_vectors.json"),
            File("datasets/test_vectors/cross_language_vectors.json")
        )
        val file = possiblePaths.firstOrNull { it.exists() }
        if (file != null) {
            val root = JSONObject(file.readText())
            val vectors = root.getJSONArray("normalization_vectors")
            for (i in 0 until vectors.length()) {
                val vec = vectors.getJSONObject(i)
                val raw = vec.getString("raw_input")
                val norm = URLNormalizer.normalize(raw)

                assertEquals("Canonical URL mismatch for $raw", vec.getString("canonical_url"), norm.canonicalUrl)
                assertEquals("url_sha256 mismatch for $raw", vec.getString("url_sha256"), norm.urlSha256)
                assertEquals("domain mismatch for $raw", vec.getString("domain"), norm.domain)
                assertEquals("domain_sha256 mismatch for $raw", vec.getString("domain_sha256"), norm.domainSha256)
                assertEquals("has_embedded_credentials mismatch for $raw", vec.getBoolean("has_embedded_credentials"), norm.hasEmbeddedCredentials)
                assertEquals("is_ip_literal mismatch for $raw", vec.getBoolean("is_ip_literal"), norm.isIpLiteral)
            }
        }
    }
}

