package ai.cyberduel.mobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class Decision {
    @SerialName("allow")
    ALLOW,

    @SerialName("warn")
    WARN,

    @SerialName("block")
    BLOCK
}

@Serializable
enum class ThreatSeverity {
    @SerialName("low")
    LOW,

    @SerialName("medium")
    MEDIUM,

    @SerialName("high")
    HIGH,

    @SerialName("critical")
    CRITICAL
}

@Serializable
enum class ProvenanceType {
    @SerialName("heuristic")
    HEURISTIC,

    @SerialName("threat_intelligence")
    THREAT_INTELLIGENCE,

    @SerialName("rule_engine")
    RULE_ENGINE,

    @SerialName("cloud_model")
    CLOUD_MODEL
}

@Serializable
enum class ReleaseChannel {
    @SerialName("development")
    DEVELOPMENT,

    @SerialName("canary")
    CANARY,

    @SerialName("stable")
    STABLE,

    @SerialName("emergency")
    EMERGENCY
}

@Serializable
enum class ReleaseStatus {
    @SerialName("draft")
    DRAFT,

    @SerialName("staged")
    STAGED,

    @SerialName("published")
    PUBLISHED,

    @SerialName("deprecated")
    DEPRECATED,

    @SerialName("revoked")
    REVOKED,

    @SerialName("rolled_back")
    ROLLED_BACK
}

@Serializable
enum class KeyStatus {
    @SerialName("active")
    ACTIVE,

    @SerialName("rotated")
    ROTATED,

    @SerialName("revoked")
    REVOKED
}

