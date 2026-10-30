package ai.cyberduel.mobile.domain.engine

import ai.cyberduel.mobile.data.model.EvidenceItem
import ai.cyberduel.mobile.data.model.ThreatSeverity
import kotlin.math.max
import kotlin.math.min

data class HeuristicOutcome(
    val score: Double,
    val evidence: List<EvidenceItem>
)

object HeuristicAnalyzer {

    val SUSPICIOUS_TLDS = setOf(
        "tk", "ml", "ga", "cf", "gq", "top", "buzz", "icu", "rest", "work"
    )

    fun analyze(features: ExtractedFeatures): HeuristicOutcome {
        val evidence = mutableListOf<EvidenceItem>()
        var score = 0.0

        // 1. Whitelist bypass
        if (features.isWhitelisted) {
            evidence.add(
                EvidenceItem(
                    ruleId = "HEUR-WHITELIST-TOP-DOMAIN",
                    description = "Verified top-tier trusted domain (${features.domain}).",
                    severity = ThreatSeverity.LOW,
                    scoreContribution = -0.80,
                    confidence = 0.95
                )
            )
            return HeuristicOutcome(score = 0.0, evidence = evidence)
        }

        // 2. Brand token impersonation
        if (features.brandTokenDetected) {
            score += 0.65
            evidence.add(
                EvidenceItem(
                    ruleId = "HEUR-BRAND-IMPERSONATION",
                    description = "Host '${features.host}' contains a high-value brand keyword on unverified domain '${features.domain}'.",
                    severity = ThreatSeverity.HIGH,
                    scoreContribution = 0.65,
                    confidence = 0.85
                )
            )
        }

        // 3. Embedded credentials in authority
        if (features.hasEmbeddedCredentials) {
            score += 0.70
            evidence.add(
                EvidenceItem(
                    ruleId = "HEUR-EMBEDDED-CREDENTIALS",
                    description = "URL authority contains embedded credentials, disguising real host.",
                    severity = ThreatSeverity.CRITICAL,
                    scoreContribution = 0.70,
                    confidence = 0.90
                )
            )
        }

        // 4. IP literal host
        if (features.isIpLiteral) {
            score += 0.50
            evidence.add(
                EvidenceItem(
                    ruleId = "HEUR-IP-LITERAL-HOST",
                    description = "Host is a raw IP literal (${features.host}) instead of a registered domain.",
                    severity = ThreatSeverity.MEDIUM,
                    scoreContribution = 0.50,
                    confidence = 0.80
                )
            )
        }

        // 5. Punycode / IDN deception
        if (features.isPunycode) {
            score += 0.55
            evidence.add(
                EvidenceItem(
                    ruleId = "HEUR-PUNYCODE-HOMOGRAPH",
                    description = "Host contains Punycode ('${features.host}'), indicating potential homograph deception.",
                    severity = ThreatSeverity.HIGH,
                    scoreContribution = 0.55,
                    confidence = 0.75
                )
            )
        }

        // 6. Suspicious TLD
        val tld = features.domain.substringAfterLast(".", "")
        if (SUSPICIOUS_TLDS.contains(tld)) {
            score += 0.35
            evidence.add(
                EvidenceItem(
                    ruleId = "HEUR-SUSPICIOUS-TLD",
                    description = "Domain uses top-level domain '.$tld' with elevated historical abuse rates.",
                    severity = ThreatSeverity.MEDIUM,
                    scoreContribution = 0.35,
                    confidence = 0.60
                )
            )
        }

        // 7. High host entropy
        if (features.hostEntropy > 4.2 && !features.isIpLiteral) {
            score += 0.30
            evidence.add(
                EvidenceItem(
                    ruleId = "HEUR-HIGH-HOST-ENTROPY",
                    description = "Host lexical entropy (${features.hostEntropy}) indicates algorithmic generation.",
                    severity = ThreatSeverity.MEDIUM,
                    scoreContribution = 0.30,
                    confidence = 0.65
                )
            )
        }

        // 8. Phishing keywords combined with suspicious characteristics
        if (features.phishKeywordCount > 0 && (score > 0.3 || features.subdomainCount > 2)) {
            val kwBonus = min(features.phishKeywordCount * 0.15, 0.40)
            score += kwBonus
            evidence.add(
                EvidenceItem(
                    ruleId = "HEUR-PHISHING-KEYWORDS",
                    description = "URL contains ${features.phishKeywordCount} credential harvesting keyword(s) in suspicious context.",
                    severity = ThreatSeverity.MEDIUM,
                    scoreContribution = kwBonus,
                    confidence = 0.70
                )
            )
        }

        val clamped = max(0.0, min(1.0, score))
        return HeuristicOutcome(
            score = Math.round(clamped * 1000.0) / 1000.0,
            evidence = evidence
        )
    }
}

