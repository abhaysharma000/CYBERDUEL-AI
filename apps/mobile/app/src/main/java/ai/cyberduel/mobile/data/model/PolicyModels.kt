package ai.cyberduel.mobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
data class RulePredicate(
    @SerialName("field") val field: String,
    @SerialName("operator") val operator: String,
    @SerialName("value") val value: JsonElement
)

@Serializable
data class DeclarativeRule(
    @SerialName("rule_id") val ruleId: String,
    @SerialName("rule_version") val ruleVersion: String = "1.0.0",
    @SerialName("name") val name: String,
    @SerialName("description") val description: String = "",
    @SerialName("severity") val severity: ThreatSeverity,
    @SerialName("action") val action: Decision,
    @SerialName("predicates") val predicates: List<RulePredicate> = emptyList(),
    @SerialName("weight") val weight: Double = 0.50
)

@Serializable
data class ThreatIndicator(
    @SerialName("indicator_id") val indicatorId: String,
    @SerialName("type") val type: String, // 'url_hash' | 'domain_hash' | 'domain' | 'prefix'
    @SerialName("value") val value: String,
    @SerialName("hash_sha256") val hashSha256: String,
    @SerialName("severity") val severity: ThreatSeverity,
    @SerialName("action") val action: Decision,
    @SerialName("description") val description: String = ""
)

@Serializable
data class ScoringThresholds(
    @SerialName("warn_threshold") val warnThreshold: Double = 0.50,
    @SerialName("block_threshold") val blockThreshold: Double = 0.85
)

@Serializable
data class PolicyBundle(
    @SerialName("bundle_id") val bundleId: String,
    @SerialName("policy_version") val policyVersion: String,
    @SerialName("sequence_number") val sequenceNumber: Long,
    @SerialName("scoring_thresholds") val scoringThresholds: ScoringThresholds = ScoringThresholds(),
    @SerialName("rules") val rules: List<DeclarativeRule> = emptyList(),
    @SerialName("threat_indicators") val threatIndicators: List<ThreatIndicator> = emptyList(),
    @SerialName("feature_weights") val featureWeights: Map<String, Double> = emptyMap(),
    @SerialName("schema_version") val schemaVersion: String = "1.0.0",
    @SerialName("created_at") val createdAt: String,
    @SerialName("expires_at") val expiresAt: String,
    @SerialName("metadata") val metadata: Map<String, String> = emptyMap()
)

