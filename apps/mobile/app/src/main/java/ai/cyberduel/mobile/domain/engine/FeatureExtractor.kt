package ai.cyberduel.mobile.domain.engine

import ai.cyberduel.mobile.data.model.NormalizedURL
import kotlin.math.log2

data class ExtractedFeatures(
    val urlLength: Int,
    val hostLength: Int,
    val pathLength: Int,
    val queryLength: Int,
    val subdomainCount: Int,
    val pathDepth: Int,
    val hasEmbeddedCredentials: Boolean,
    val isIpLiteral: Boolean,
    val isPunycode: Boolean,
    val brandTokenDetected: Boolean,
    val hasNonStandardPort: Boolean,
    val phishKeywordCount: Int,
    val hostEntropy: Double,
    val scheme: String,
    val host: String,
    val unicodeHost: String,
    val port: Int,
    val domain: String,
    val isWhitelisted: Boolean
) {
    fun getFeatureValue(field: String): Any? {
        return when (field) {
            "url_length" -> urlLength
            "host_length" -> hostLength
            "path_length" -> pathLength
            "query_length" -> queryLength
            "subdomain_count" -> subdomainCount
            "path_depth" -> pathDepth
            "has_embedded_credentials" -> hasEmbeddedCredentials
            "is_ip_literal" -> isIpLiteral
            "is_punycode" -> isPunycode
            "brand_token_detected" -> brandTokenDetected
            "has_non_standard_port" -> hasNonStandardPort
            "phish_keyword_count" -> phishKeywordCount
            "host_entropy" -> hostEntropy
            "scheme" -> scheme
            "host" -> host
            "unicode_host" -> unicodeHost
            "port" -> port
            "domain" -> domain
            "is_whitelisted" -> isWhitelisted
            else -> null
        }
    }
}

object FeatureExtractor {

    val HIGH_VALUE_BRANDS = setOf(
        "paypal", "microsoft", "apple", "google", "netflix", "amazon",
        "chase", "wellsfargo", "bankofamerica", "binance", "coinbase",
        "dropbox", "facebook", "instagram", "linkedin", "adobe", "docusign"
    )

    val OFFICIAL_BRAND_DOMAINS: Map<String, Set<String>> = mapOf(
        "paypal" to setOf("paypal.com", "paypal.me"),
        "microsoft" to setOf("microsoft.com", "live.com", "office.com", "azure.com"),
        "apple" to setOf("apple.com", "icloud.com"),
        "google" to setOf("google.com", "gmail.com", "youtube.com"),
        "netflix" to setOf("netflix.com"),
        "amazon" to setOf("amazon.com", "aws.amazon.com"),
        "chase" to setOf("chase.com"),
        "wellsfargo" to setOf("wellsfargo.com"),
        "bankofamerica" to setOf("bankofamerica.com"),
        "binance" to setOf("binance.com"),
        "coinbase" to setOf("coinbase.com"),
        "dropbox" to setOf("dropbox.com"),
        "facebook" to setOf("facebook.com", "meta.com"),
        "instagram" to setOf("instagram.com"),
        "linkedin" to setOf("linkedin.com"),
        "adobe" to setOf("adobe.com"),
        "docusign" to setOf("docusign.com")
    )

    val TRUSTED_TOP_DOMAINS = setOf(
        "google.com", "apple.com", "microsoft.com", "amazon.com", "github.com",
        "wikipedia.org", "cloudflare.com", "mozilla.org", "python.org",
        "w3.org", "eff.org", "nist.gov"
    )

    val PHISHING_KEYWORDS = setOf(
        "login", "signin", "verify", "verification", "account-update",
        "security-check", "confirm-identity", "wallet-connect", "billing-update",
        "password-reset", "secure-banking"
    )

    fun extract(url: NormalizedURL): ExtractedFeatures {
        val hostEntropy = calculateEntropy(url.host)

        val pathSegments = url.path.split('/').filter { it.isNotEmpty() }
        val pathDepth = pathSegments.size

        var brandDetected = false
        for (brand in HIGH_VALUE_BRANDS) {
            if (url.host.contains(brand)) {
                val officialSet = OFFICIAL_BRAND_DOMAINS[brand]
                if (officialSet == null || !officialSet.contains(url.domain)) {
                    brandDetected = true
                    break
                }
            }
        }

        val fullText = "${url.host} ${url.path} ${url.query ?: ""}".lowercase()
        var keywordCount = 0
        for (kw in PHISHING_KEYWORDS) {
            if (fullText.contains(kw)) {
                keywordCount++
            }
        }

        val isWhitelisted = TRUSTED_TOP_DOMAINS.contains(url.domain)
        val hasNonStandardPort = url.port != null && url.port != 80 && url.port != 443

        return ExtractedFeatures(
            urlLength = url.canonicalUrl.length,
            hostLength = url.host.length,
            pathLength = url.path.length,
            queryLength = url.query?.length ?: 0,
            subdomainCount = url.subdomains.size,
            pathDepth = pathDepth,
            hasEmbeddedCredentials = url.hasEmbeddedCredentials,
            isIpLiteral = url.isIpLiteral,
            isPunycode = url.isPunycode,
            brandTokenDetected = brandDetected,
            hasNonStandardPort = hasNonStandardPort,
            phishKeywordCount = keywordCount,
            hostEntropy = Math.round(hostEntropy * 1000.0) / 1000.0,
            scheme = url.scheme,
            host = url.host,
            unicodeHost = url.unicodeHost,
            port = url.port ?: if (url.scheme == "https") 443 else 80,
            domain = url.domain,
            isWhitelisted = isWhitelisted
        )
    }

    fun calculateEntropy(str: String): Double {
        if (str.isEmpty()) return 0.0
        val freq = mutableMapOf<Char, Int>()
        for (c in str) {
            freq[c] = freq.getOrDefault(c, 0) + 1
        }
        val len = str.length.toDouble()
        var entropy = 0.0
        for (count in freq.values) {
            val p = count / len
            entropy -= p * log2(p)
        }
        return entropy
    }
}

