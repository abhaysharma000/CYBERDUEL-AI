package ai.cyberduel.mobile.domain.engine

import ai.cyberduel.mobile.data.model.NormalizedURL
import ai.cyberduel.mobile.domain.crypto.DigestUtil
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

class URLNormalizationException(message: String, val code: String = "INVALID_URL") : IllegalArgumentException(message)

object URLNormalizer {

    private const val MAX_URL_LENGTH = 4096
    private const val MAX_HOST_LENGTH = 253

    private val SUPPORTED_SCHEMES = setOf("http", "https")

    private val SENSITIVE_QUERY_PARAMS = setOf(
        "token", "access_token", "auth", "key", "apikey", "api_key",
        "password", "passwd", "secret", "session", "sessionid", "session_id",
        "jwt", "bearer", "code", "pin", "otp"
    )

    fun normalize(rawInput: String): NormalizedURL {
        val cleaned = rawInput.trim()
        if (cleaned.isEmpty()) {
            throw URLNormalizationException("URL input cannot be empty.", "EMPTY_INPUT")
        }
        if (cleaned.length > MAX_URL_LENGTH) {
            throw URLNormalizationException("URL exceeds maximum length of $MAX_URL_LENGTH.", "URL_TOO_LONG")
        }

        // Check for control characters
        for (c in cleaned) {
            if (c.code < 32 || c.code == 127) {
                throw URLNormalizationException("URL contains forbidden control characters.", "CONTROL_CHARACTERS")
            }
        }

        val uri = try {
            URI(cleaned)
        } catch (e: Exception) {
            throw URLNormalizationException("URL parsing failed: ${e.message}", "PARSE_ERROR")
        }

        // 1. Validate Scheme
        val rawScheme = uri.scheme?.lowercase()
            ?: throw URLNormalizationException("URL scheme is missing.", "MISSING_SCHEME")

        if (!SUPPORTED_SCHEMES.contains(rawScheme)) {
            throw URLNormalizationException("Unsupported URL scheme '$rawScheme'.", "UNSUPPORTED_SCHEME")
        }
        val scheme = rawScheme

        // 2. Extract Authority, Host & Credentials
        val rawAuthority = uri.rawAuthority
            ?: throw URLNormalizationException("URL authority/hostname is missing.", "MISSING_HOSTNAME")

        var hasEmbeddedCredentials = false
        var userinfo: String? = null
        var hostPortPart = rawAuthority

        if (rawAuthority.contains("@")) {
            hasEmbeddedCredentials = true
            val parts = rawAuthority.split("@", limit = 2)
            val rawUser = parts[0]
            userinfo = if (rawUser.contains(":")) {
                val user = rawUser.split(":", limit = 2)[0]
                "$user:[REDACTED]"
            } else {
                rawUser
            }
            hostPortPart = parts[1]
        }

        // Parse host and port
        var rawHost: String
        var port: Int? = null

        if (hostPortPart.startsWith("[")) {
            // IPv6 literal
            val endIdx = hostPortPart.indexOf("]")
            if (endIdx == -1) {
                throw URLNormalizationException("Malformed IPv6 authority bracket.", "INVALID_IPV6")
            }
            rawHost = hostPortPart.substring(0, endIdx + 1)
            val portPart = hostPortPart.substring(endIdx + 1)
            if (portPart.startsWith(":")) {
                port = portPart.substring(1).toIntOrNull()
            }
        } else if (hostPortPart.contains(":")) {
            val parts = hostPortPart.split(":", limit = 2)
            rawHost = parts[0]
            port = parts[1].toIntOrNull()
        } else {
            rawHost = hostPortPart
        }

        var host = rawHost.lowercase().trimEnd('.')
        if (host.isEmpty()) {
            throw URLNormalizationException("Hostname cannot be empty.", "EMPTY_HOSTNAME")
        }
        if (host.length > MAX_HOST_LENGTH) {
            throw URLNormalizationException("Hostname exceeds maximum length of $MAX_HOST_LENGTH.", "HOST_TOO_LONG")
        }

        // IP Literal check
        val isIpV4 = host.matches(Regex("""^(\d{1,3}\.){3}\d{1,3}$"""))
        val isIpV6 = host.startsWith("[") && host.endsWith("]")
        val isIpLiteral = isIpV4 || isIpV6

        // Punycode & IDN
        var isPunycode = false
        val unicodeHost = host
        if (!isIpLiteral) {
            if (host.startsWith("xn--") || host.contains(".xn--")) {
                isPunycode = true
            }
        }

        // Default port normalization
        if ((scheme == "http" && port == 80) || (scheme == "https" && port == 443)) {
            port = null
        }

        // 3. Domain and Subdomains
        val (domain, subdomains) = extractDomainAndSubdomains(host, isIpLiteral)

        // 4. Path Normalization (dot segments)
        val rawPath = uri.rawPath.ifEmpty { "/" }
        val normalizedPath = normalizePath(rawPath)

        // 5. Query Normalization & Sensitive Parameter Redaction
        val normalizedQuery = if (!uri.rawQuery.isNullOrEmpty()) {
            normalizeQuery(uri.rawQuery)
        } else {
            null
        }

        // 6. Fragment
        val fragment = uri.rawFragment

        // 7. Canonical URL Construction
        val portStr = if (port != null) ":$port" else ""
        val queryStr = if (normalizedQuery != null) "?$normalizedQuery" else ""
        val canonicalUrl = "$scheme://$host$portStr$normalizedPath$queryStr"

        // 8. Cryptographic Digests
        val urlSha256 = DigestUtil.sha256Hex(canonicalUrl)
        val domainSha256 = DigestUtil.sha256Hex(domain)

        return NormalizedURL(
            rawInput = cleaned,
            scheme = scheme,
            host = host,
            unicodeHost = unicodeHost,
            port = port,
            path = normalizedPath,
            query = normalizedQuery,
            fragment = fragment,
            canonicalUrl = canonicalUrl,
            domain = domain,
            subdomains = subdomains,
            urlSha256 = urlSha256,
            domainSha256 = domainSha256,
            hasEmbeddedCredentials = hasEmbeddedCredentials,
            userinfo = userinfo,
            isIpLiteral = isIpLiteral,
            isPunycode = isPunycode
        )
    }

    private fun extractDomainAndSubdomains(host: String, isIpLiteral: Boolean): Pair<String, List<String>> {
        if (isIpLiteral) return Pair(host, emptyList())

        val parts = host.split('.')
        if (parts.size <= 1) return Pair(host, emptyList())

        val secondLevelTlds = setOf("co", "com", "org", "net", "edu", "gov", "mil", "ac")
        val domain: String
        val subdomains: List<String>

        if (parts.size >= 3 && secondLevelTlds.contains(parts[parts.size - 2])) {
            domain = parts.takeLast(3).joinToString(".")
            subdomains = parts.dropLast(3)
        } else {
            domain = parts.takeLast(2).joinToString(".")
            subdomains = parts.dropLast(2)
        }
        return Pair(domain, subdomains)
    }

    private fun normalizePath(rawPath: String): String {
        val segments = rawPath.split('/')
        val output = mutableListOf<String>()

        for (segment in segments) {
            if (segment.isEmpty() || segment == ".") continue
            if (segment == "..") {
                if (output.isNotEmpty()) output.removeAt(output.size - 1)
            } else {
                output.add(segment)
            }
        }

        val resolved = "/" + output.joinToString("/")
        return if (rawPath.endsWith("/") && !resolved.endsWith("/")) "$resolved/" else resolved
    }

    private fun normalizeQuery(rawQuery: String): String {
        val pairs = rawQuery.split("&")
        val sortedList = mutableListOf<Pair<String, String>>()

        for (pair in pairs) {
            if (pair.isEmpty()) continue
            val parts = pair.split("=", limit = 2)
            val key = try {
                URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name())
            } catch (_: Exception) {
                parts[0]
            }
            val value = if (parts.size > 1) {
                try {
                    URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name())
                } catch (_: Exception) {
                    parts[1]
                }
            } else {
                ""
            }

            val finalValue = if (SENSITIVE_QUERY_PARAMS.contains(key.lowercase())) {
                "[REDACTED]"
            } else {
                value
            }

            sortedList.add(Pair(key, finalValue))
        }

        sortedList.sortBy { it.first }

        return sortedList.joinToString("&") { (k, v) ->
            val encK = URLEncoder.encode(k, StandardCharsets.UTF_8.name())
            val encV = URLEncoder.encode(v, StandardCharsets.UTF_8.name())
            "$encK=$encV"
        }
    }
}

