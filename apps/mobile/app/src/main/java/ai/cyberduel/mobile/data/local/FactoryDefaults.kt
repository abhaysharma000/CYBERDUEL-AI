package ai.cyberduel.mobile.data.local

import ai.cyberduel.mobile.data.model.Decision
import ai.cyberduel.mobile.data.model.DeclarativeRule
import ai.cyberduel.mobile.data.model.KeyStatus
import ai.cyberduel.mobile.data.model.PolicyBundle
import ai.cyberduel.mobile.data.model.RulePredicate
import ai.cyberduel.mobile.data.model.ScoringThresholds
import ai.cyberduel.mobile.data.model.SigningKeyMetadata
import ai.cyberduel.mobile.data.model.ThreatIndicator
import ai.cyberduel.mobile.data.model.ThreatSeverity
import ai.cyberduel.mobile.data.model.TrustAnchorSet
import kotlinx.serialization.json.JsonPrimitive

object FactoryDefaults {

    val FACTORY_TRUST_ANCHORS = TrustAnchorSet(
        activeKeys = listOf(
            SigningKeyMetadata(
                keyId = "cyberduel-prod-2026-k1",
                algorithm = "ed25519",
                publicKeyPem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAObvvQ00bruMF1ZvF33Cfr5GnaEstiK8R1dJqpX8dSBI=\n-----END PUBLIC KEY-----\n",
                status = KeyStatus.ACTIVE,
                validFrom = "2026-10-01T00:00:00Z",
                validUntil = "2028-10-01T00:00:00Z"
            )
        ),
        revokedKeys = emptyList(),
        timestamp = "2026-10-01T00:00:00Z"
    )

    val FACTORY_POLICY_BUNDLE = PolicyBundle(
        bundleId = "00000000-0000-0000-0000-000000000001",
        policyVersion = "2026.10.1",
        sequenceNumber = 1L,
        scoringThresholds = ScoringThresholds(
            warnThreshold = 0.50,
            blockThreshold = 0.85
        ),
        rules = listOf(
            DeclarativeRule(
                ruleId = "RULE-EMBEDDED-CREDENTIALS",
                ruleVersion = "1.0.0",
                name = "Disguised Authority Credential Injection",
                description = "Blocks URLs containing embedded username or password authentication syntax.",
                severity = ThreatSeverity.CRITICAL,
                action = Decision.BLOCK,
                predicates = listOf(
                    RulePredicate(
                        field = "has_embedded_credentials",
                        operator = "eq",
                        value = JsonPrimitive(true)
                    )
                ),
                weight = 0.95
            ),
            DeclarativeRule(
                ruleId = "RULE-UNVERIFIED-BRAND-MIMICRY",
                ruleVersion = "1.0.0",
                name = "Unverified High-Value Brand Mimicry",
                description = "Warns on destinations containing target brand names hosted on non-official domains.",
                severity = ThreatSeverity.HIGH,
                action = Decision.WARN,
                predicates = listOf(
                    RulePredicate(
                        field = "brand_token_detected",
                        operator = "eq",
                        value = JsonPrimitive(true)
                    )
                ),
                weight = 0.65
            ),
            DeclarativeRule(
                ruleId = "RULE-RAW-IP-HOST-WITH-KEYWORDS",
                ruleVersion = "1.0.0",
                name = "Raw IP Host with Phishing Tokens",
                description = "Warns when an IP address literal is used alongside credential harvesting keywords.",
                severity = ThreatSeverity.HIGH,
                action = Decision.WARN,
                predicates = listOf(
                    RulePredicate(
                        field = "is_ip_literal",
                        operator = "eq",
                        value = JsonPrimitive(true)
                    ),
                    RulePredicate(
                        field = "phish_keyword_count",
                        operator = "gt",
                        value = JsonPrimitive(0)
                    )
                ),
                weight = 0.75
            )
        ),
        threatIndicators = listOf(
            ThreatIndicator(
                indicatorId = "IND-MALICIOUS-TEST-DOMAIN",
                type = "domain",
                value = "malicious-phish-portal.test",
                hashSha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                severity = ThreatSeverity.CRITICAL,
                action = Decision.BLOCK,
                description = "Known confirmed phishing testing portal."
            )
        ),
        featureWeights = mapOf(
            "brand_token_detected" to 0.65,
            "has_embedded_credentials" to 0.70,
            "is_ip_literal" to 0.50,
            "is_punycode" to 0.55
        ),
        schemaVersion = "1.0.0",
        createdAt = "2026-10-01T00:00:00Z",
        expiresAt = "2027-12-31T23:59:59Z",
        metadata = mapOf(
            "origin" to "factory_bootstrap",
            "build" to "2026.10-release"
        )
    )
}

