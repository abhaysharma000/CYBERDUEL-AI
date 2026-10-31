package ai.cyberduel.mobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class NormalizedURL(
    @SerialName("raw_input") val rawInput: String,
    @SerialName("scheme") val scheme: String,
    @SerialName("host") val host: String,
    @SerialName("unicode_host") val unicodeHost: String,
    @SerialName("port") val port: Int? = null,
    @SerialName("path") val path: String,
    @SerialName("query") val query: String? = null,
    @SerialName("fragment") val fragment: String? = null,
    @SerialName("canonical_url") val canonicalUrl: String,
    @SerialName("domain") val domain: String,
    @SerialName("subdomains") val subdomains: List<String> = emptyList(),
    @SerialName("url_sha256") val urlSha256: String,
    @SerialName("domain_sha256") val domainSha256: String,
    @SerialName("has_embedded_credentials") val hasEmbeddedCredentials: Boolean = false,
    @SerialName("userinfo") val userinfo: String? = null,
    @SerialName("is_ip_literal") val isIpLiteral: Boolean = false,
    @SerialName("is_punycode") val isPunycode: Boolean = false
)

@Serializable
data class EvidenceItem(
    @SerialName("rule_id") val ruleId: String,
    @SerialName("description") val description: String,
    @SerialName("severity") val severity: ThreatSeverity,
    @SerialName("score_contribution") val scoreContribution: Double,
    @SerialName("confidence") val confidence: Double = 0.90,
    @SerialName("metadata") val metadata: Map<String, String> = emptyMap()
)

@Serializable
data class LocalThreatResult(
    @SerialName("decision") val decision: Decision,
    @SerialName("risk_score") val riskScore: Double,
    @SerialName("confidence") val confidence: Double,
    @SerialName("evidence") val evidence: List<EvidenceItem>,
    @SerialName("explanation") val explanation: String,
    @SerialName("policy_version") val policyVersion: String,
    @SerialName("matched_rules") val matchedRules: List<String>,
    @SerialName("provenance") val provenance: ProvenanceType,
    @SerialName("is_stale") val isStale: Boolean = false,
    @SerialName("evaluated_at") val evaluatedAt: String
)

