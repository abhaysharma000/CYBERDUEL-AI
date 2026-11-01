package ai.cyberduel.mobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
data class ThreatObservationReport(
    @SerialName("observation_id") val observationId: String,
    @SerialName("source") val source: String = "mobile_app",
    @SerialName("normalized_target") val normalizedTarget: String,
    @SerialName("observed_at") val observedAt: String,
    @SerialName("local_action_taken") val localActionTaken: Decision? = null,
    @SerialName("engine_version") val engineVersion: String = "1.0.0",
    @SerialName("policy_version") val policyVersion: String,
    @SerialName("telemetry_summary") val telemetrySummary: JsonObject = JsonObject(emptyMap())
)

