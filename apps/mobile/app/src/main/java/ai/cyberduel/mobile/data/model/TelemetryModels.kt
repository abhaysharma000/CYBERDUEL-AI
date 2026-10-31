package ai.cyberduel.mobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
data class ThreatObservationReport(
    @SerialName("observation_id") val observationId: String,
    @SerialName("reported_at") val reportedAt: String,
    @SerialName("source") val source: String = "mobile_agent",
    @SerialName("normalized_identifier") val normalizedIdentifier: String, // SHA-256 target digest
    @SerialName("observed_url") val observedUrl: String? = null,
    @SerialName("detected_features") val detectedFeatures: JsonObject,
    @SerialName("initial_decision") val initialDecision: Decision,
    @SerialName("initial_risk_score") val initialRiskScore: Double,
    @SerialName("client_policy_version") val clientPolicyVersion: String,
    @SerialName("context") val context: JsonObject
)

