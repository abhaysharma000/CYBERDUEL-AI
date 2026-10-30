package ai.cyberduel.mobile.domain.crypto

import org.json.JSONArray
import org.json.JSONObject
import java.util.TreeMap

/**
 * CyberDuel AI — Canonical JSON Serializer (RFC 8785 subset)
 * Produces deterministic, sorted, compact UTF-8 JSON bytes identical to Python and TypeScript engines.
 */
object CanonicalJson {

    fun canonicalize(jsonStr: String): ByteArray {
        val trimmed = jsonStr.trim()
        val canonicalStr = when {
            trimmed.startsWith("{") -> {
                val jsonObject = JSONObject(trimmed)
                canonicalizeObject(jsonObject)
            }
            trimmed.startsWith("[") -> {
                val jsonArray = JSONArray(trimmed)
                canonicalizeArray(jsonArray)
            }
            else -> trimmed
        }
        return canonicalStr.toByteArray(Charsets.UTF_8)
    }

    fun canonicalizeToString(jsonStr: String): String = canonicalize(jsonStr).decodeToString()

    fun getManifestSigningPayload(manifestJsonStr: String): ByteArray {
        val jsonObject = JSONObject(manifestJsonStr)
        // Strictly exclude the 'signature' field from the signing payload
        jsonObject.remove("signature")
        return canonicalize(jsonObject.toString())
    }

    fun getManifestSigningPayloadString(manifestJsonStr: String): String =
        getManifestSigningPayload(manifestJsonStr).decodeToString()

    private fun canonicalizeObject(obj: JSONObject): String {
        val sortedMap = TreeMap<String, Any?>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            sortedMap[key] = obj.get(key)
        }

        val sb = StringBuilder("{")
        var first = true
        for ((key, value) in sortedMap) {
            if (!first) sb.append(",")
            sb.append("\"").append(escapeString(key)).append("\":")
            sb.append(canonicalizeValue(value))
            first = false
        }
        sb.append("}")
        return sb.toString()
    }

    private fun canonicalizeArray(arr: JSONArray): String {
        val sb = StringBuilder("[")
        for (i in 0 until arr.length()) {
            if (i > 0) sb.append(",")
            sb.append(canonicalizeValue(arr.get(i)))
        }
        sb.append("]")
        return sb.toString()
    }

    private fun canonicalizeValue(value: Any?): String {
        return when (value) {
            null, JSONObject.NULL -> "null"
            is JSONObject -> canonicalizeObject(value)
            is JSONArray -> canonicalizeArray(value)
            is String -> {
                // Normalize UTC timezone formatting (+00:00 -> Z)
                val normalized = if (value.endsWith("+00:00")) {
                    value.substring(0, value.length - 6) + "Z"
                } else {
                    value
                }
                "\"${escapeString(normalized)}\""
            }
            is Boolean -> if (value) "true" else "false"
            is Number -> {
                if (value is Double || value is Float) {
                    val d = value.toDouble()
                    if (d == d.toLong().toDouble()) {
                        // Integer representation
                        d.toLong().toString()
                    } else {
                        d.toString()
                    }
                } else {
                    value.toString()
                }
            }
            else -> "\"${escapeString(value.toString())}\""
        }
    }

    private fun escapeString(s: String): String {
        val sb = StringBuilder()
        for (c in s) {
            when (c) {
                '\"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    if (c.code in 0..31) {
                        sb.append(String.format("\\u%04x", c.code))
                    } else {
                        sb.append(c)
                    }
                }
            }
        }
        return sb.toString()
    }
}

