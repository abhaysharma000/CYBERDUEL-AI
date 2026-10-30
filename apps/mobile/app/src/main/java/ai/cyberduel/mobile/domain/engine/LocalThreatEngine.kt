package ai.cyberduel.mobile.domain.engine

import ai.cyberduel.mobile.data.model.Decision
import ai.cyberduel.mobile.data.model.EvidenceItem
import ai.cyberduel.mobile.data.model.LocalThreatResult
import ai.cyberduel.mobile.data.model.NormalizedURL
import ai.cyberduel.mobile.data.model.PolicyBundle
import ai.cyberduel.mobile.data.model.ProvenanceType
import ai.cyberduel.mobile.data.model.ThreatSeverity
import java.time.Instant
import java.time.format.DateTimeFormatter
import kotlin.math.max
import kotlin.math.min
import kotlin.math.round

class LocalThreatEngine(private var activePolicy: PolicyBundle) {

    fun updatePolicy(newPolicy: PolicyBundle) {
        this.activePolicy = newPolicy
    }

    fun getPolicy(): PolicyBundle = activePolicy

    fun getPolicyVersion(): String = activePolicy.policyVersion

    fun evaluate(rawUrl: String): LocalThreatResult {
        val now = Instant.now()
        val evaluatedAt = DateTimeFormatter.ISO_INSTANT.format(now)

        val isStale = try {
            Instant.parse(activePolicy.expiresAt).isBefore(now)
        } catch (_: Exception) {
            false
        }

        // 1. Safe URL normalization
        val normalized: NormalizedURL = try {
            URLNormalizer.normalize(rawUrl)
        } catch (e: Exception) {
            val msg = e.message ?: "Invalid or unparseable URL"
            return LocalThreatResult(
                decision = Decision.ALLOW, // Unsupported/unparseable schemes are not blocked
                riskScore = 0.0,
                confidence = 0.1,
                evidence = listOf(
                    EvidenceItem(
                        ruleId = "NORM-UNSUPPORTED-OR-INVALID",
                        description = "URL could not be parsed: $msg",
                        severity = ThreatSeverity.LOW,
                        scoreContribution = 0.0,
                        confidence = 0.1
                    )
                ),
                explanation = "Destination URL could not be normalized: $msg",
                policyVersion = activePolicy.policyVersion,
                matchedRules = emptyList(),
                provenance = ProvenanceType.HEURISTIC,
                isStale = isStale,
                evaluatedAt = evaluatedAt
            )
        }

        // 2. Exact Threat Indicator Lookup (High-Confidence Threat Intelligence)
        for (indicator in activePolicy.threatIndicators) {
            var matched = false
            when (indicator.type) {
                "url_hash" -> if (indicator.hashSha256.equals(normalized.urlSha256, ignoreCase = true)) matched = true
                "domain_hash" -> if (indicator.hashSha256.equals(normalized.domainSha256, ignoreCase = true)) matched = true
                "domain" -> if (indicator.value.equals(normalized.domain, ignoreCase = true)) matched = true
            }

            if (matched) {
                val evidence = EvidenceItem(
                    ruleId = "IND-${indicator.indicatorId}",
                    description = indicator.description.ifEmpty { "Confirmed threat indicator match for ${indicator.value}" },
                    severity = indicator.severity,
                    scoreContribution = 1.0,
                    confidence = 0.99,
                    metadata = mapOf(
                        "indicator_type" to indicator.type,
                        "indicator_value" to indicator.value
                    )
                )

                return LocalThreatResult(
                    decision = indicator.action,
                    riskScore = 1.0,
                    confidence = 0.99,
                    evidence = listOf(evidence),
                    explanation = "Confirmed malicious destination matching threat intelligence record '${indicator.indicatorId}'.",
                    policyVersion = activePolicy.policyVersion,
                    matchedRules = listOf(indicator.indicatorId),
                    provenance = ProvenanceType.THREAT_INTELLIGENCE,
                    isStale = isStale,
                    evaluatedAt = evaluatedAt
                )
            }
        }

        // 3. Extract Features
        val features = FeatureExtractor.extract(normalized)

        // 4. Declarative Rules Evaluation
        val allEvidence = mutableListOf<EvidenceItem>()
        val matchedRules = mutableListOf<String>()
        var ruleMaxAction = Decision.ALLOW
        var ruleScoreSum = 0.0

        for (rule in activePolicy.rules) {
            val outcome = DeclarativeRuleEvaluator.evaluateRule(rule, features)
            if (outcome != null && outcome.matched) {
                matchedRules.add(outcome.ruleId)
                allEvidence.add(outcome.evidence)
                ruleScoreSum += outcome.weight

                if (outcome.action == Decision.BLOCK) {
                    ruleMaxAction = Decision.BLOCK
                } else if (outcome.action == Decision.WARN && ruleMaxAction != Decision.BLOCK) {
                    ruleMaxAction = Decision.WARN
                }
            }
        }

        // If an explicit declarative rule fired with action 'block', enforce it
        if (ruleMaxAction == Decision.BLOCK) {
            return LocalThreatResult(
                decision = Decision.BLOCK,
                riskScore = min(1.0, max(0.85, ruleScoreSum)),
                confidence = 0.92,
                evidence = allEvidence,
                explanation = "Blocked by active declarative defense policy rule(s): ${matchedRules.joinToString(", ")}.",
                policyVersion = activePolicy.policyVersion,
                matchedRules = matchedRules,
                provenance = ProvenanceType.RULE_ENGINE,
                isStale = isStale,
                evaluatedAt = evaluatedAt
            )
        }

        // 5. Heuristic Analysis
        val heuristicOutcome = HeuristicAnalyzer.analyze(features)
        allEvidence.addAll(heuristicOutcome.evidence)

        // 6. Aggregate Scoring
        val totalScore = min(1.0, max(heuristicOutcome.score, ruleScoreSum))
        val warnThresh = activePolicy.scoringThresholds.warnThreshold
        val blockThresh = activePolicy.scoringThresholds.blockThreshold

        var decision = Decision.ALLOW
        var explanation = "Destination exhibits standard benign characteristics."
        var provenance = ProvenanceType.HEURISTIC

        if (ruleMaxAction == Decision.WARN || totalScore >= blockThresh) {
            if (totalScore >= blockThresh) {
                decision = Decision.BLOCK
                explanation = "Destination exceeds malicious risk threshold (%.2f >= %.2f).".format(totalScore, blockThresh)
            } else {
                decision = Decision.WARN
                explanation = "Destination exhibits suspicious indicators requiring caution (%.2f >= %.2f).".format(totalScore, warnThresh)
            }
            provenance = if (matchedRules.isNotEmpty()) ProvenanceType.RULE_ENGINE else ProvenanceType.HEURISTIC
        } else if (totalScore >= warnThresh) {
            decision = Decision.WARN
            explanation = "Destination exhibits suspicious indicators requiring caution (%.2f >= %.2f).".format(totalScore, warnThresh)
            provenance = ProvenanceType.HEURISTIC
        }

        val confidence = if (allEvidence.isNotEmpty()) 0.85 else 0.60
        val roundedRiskScore = round(totalScore * 1000) / 1000.0

        return LocalThreatResult(
            decision = decision,
            riskScore = roundedRiskScore,
            confidence = confidence,
            evidence = allEvidence,
            explanation = explanation,
            policyVersion = activePolicy.policyVersion,
            matchedRules = matchedRules,
            provenance = provenance,
            isStale = isStale,
            evaluatedAt = evaluatedAt
        )
    }
}

