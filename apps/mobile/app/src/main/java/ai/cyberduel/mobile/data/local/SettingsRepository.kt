package ai.cyberduel.mobile.data.local

import android.content.Context
import android.content.SharedPreferences
import ai.cyberduel.mobile.data.model.Decision
import ai.cyberduel.mobile.data.model.LocalThreatResult
import ai.cyberduel.mobile.data.model.ReleaseChannel
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.UUID

@Serializable
data class HistoryEntry(
    val id: String = UUID.randomUUID().toString(),
    val rawUrl: String,
    val decision: Decision,
    val riskScore: Double,
    val explanation: String,
    val timestamp: String
)

class SettingsRepository(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences("cyberduel_settings", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }

    var isProtectionEnabled: Boolean
        get() = prefs.getBoolean(KEY_PROTECTION_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_PROTECTION_ENABLED, value).apply()

    var isTelemetryEnabled: Boolean
        get() = prefs.getBoolean(KEY_TELEMETRY_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_TELEMETRY_ENABLED, value).apply()

    var releaseChannel: ReleaseChannel
        get() {
            val name = prefs.getString(KEY_RELEASE_CHANNEL, ReleaseChannel.STABLE.name) ?: ReleaseChannel.STABLE.name
            return try {
                ReleaseChannel.valueOf(name)
            } catch (_: Exception) {
                ReleaseChannel.STABLE
            }
        }
        set(value) = prefs.edit().putString(KEY_RELEASE_CHANNEL, value.name).apply()

    var backendUrl: String
        get() {
            val url = prefs.getString(KEY_BACKEND_URL, DEFAULT_BACKEND_URL) ?: DEFAULT_BACKEND_URL
            if (url.contains("cyberduel-ai-1.onrender.com") || url.contains("localhost")) {
                prefs.edit().putString(KEY_BACKEND_URL, DEFAULT_BACKEND_URL).apply()
                return DEFAULT_BACKEND_URL
            }
            return url
        }
        set(value) = prefs.edit().putString(KEY_BACKEND_URL, value.trimEnd('/')).apply()

    val clientId: String
        get() {
            var id = prefs.getString(KEY_CLIENT_ID, null)
            if (id == null) {
                id = UUID.randomUUID().toString()
                prefs.edit().putString(KEY_CLIENT_ID, id).apply()
            }
            return id
        }

    var lastUpdateCheckTimestamp: Long
        get() = prefs.getLong(KEY_LAST_UPDATE_CHECK, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_UPDATE_CHECK, value).apply()

    fun getHistory(): List<HistoryEntry> {
        val raw = prefs.getString(KEY_THREAT_HISTORY, null) ?: return emptyList()
        return try {
            json.decodeFromString<List<HistoryEntry>>(raw)
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun addHistoryEntry(url: String, result: LocalThreatResult) {
        val current = getHistory().toMutableList()
        val entry = HistoryEntry(
            rawUrl = url,
            decision = result.decision,
            riskScore = result.riskScore,
            explanation = result.explanation,
            timestamp = result.evaluatedAt
        )
        current.add(0, entry)
        // Keep last 50 entries
        val trimmed = if (current.size > 50) current.subList(0, 50) else current
        prefs.edit().putString(KEY_THREAT_HISTORY, json.encodeToString(trimmed)).apply()
    }

    fun clearHistory() {
        prefs.edit().remove(KEY_THREAT_HISTORY).apply()
    }

    companion object {
        private const val KEY_PROTECTION_ENABLED = "protection_enabled"
        private const val KEY_TELEMETRY_ENABLED = "telemetry_enabled"
        private const val KEY_RELEASE_CHANNEL = "release_channel"
        private const val KEY_BACKEND_URL = "backend_url"
        private const val KEY_CLIENT_ID = "client_id"
        private const val KEY_LAST_UPDATE_CHECK = "last_update_check"
        private const val KEY_THREAT_HISTORY = "threat_history"

        // Default to Render production backend (or override via settings screen)
        const val DEFAULT_BACKEND_URL = "https://cyberduel-ai-pabz.onrender.com"
    }
}

