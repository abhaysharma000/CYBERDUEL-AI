package ai.cyberduel.mobile.domain.engine

import ai.cyberduel.mobile.data.model.Decision
import ai.cyberduel.mobile.data.model.DeclarativeRule
import ai.cyberduel.mobile.data.model.EvidenceItem
import ai.cyberduel.mobile.data.model.RulePredicate
import ai.cyberduel.mobile.data.model.ThreatSeverity
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

data class EvaluatedRuleOutcome(
    val matched: Boolean,
    val ruleId: String,
    val ruleVersion: String,
    val action: Decision,
    val severity: ThreatSeverity,
    val weight: Double,
    val evidence: EvidenceItem
)

object DeclarativeRuleEvaluator {

    fun evaluateRule(rule: DeclarativeRule, features: ExtractedFeatures): EvaluatedRuleOutcome? {
        if (rule.predicates.isEmpty()) {
            return null
        }

        // All predicates must evaluate to true (logical AND)
        for (predicate in rule.predicates) {
            if (!evaluatePredicate(predicate, features)) {
                return null
            }
        }

        val evidence = EvidenceItem(
            ruleId = rule.ruleId,
            description = rule.description.ifEmpty { "Matched declarative defensive rule ${rule.ruleId}" },
            severity = rule.severity,
            scoreContribution = rule.weight,
            confidence = 0.90,
            metadata = mapOf(
                "rule_version" to rule.ruleVersion,
                "action" to rule.action.name.lowercase()
            )
        )

        return EvaluatedRuleOutcome(
            matched = true,
            ruleId = rule.ruleId,
            ruleVersion = rule.ruleVersion,
            action = rule.action,
            severity = rule.severity,
            weight = rule.weight,
            evidence = evidence
        )
    }

    private fun evaluatePredicate(predicate: RulePredicate, features: ExtractedFeatures): Boolean {
        val featureVal = features.getFeatureValue(predicate.field) ?: return false
        val targetElem = predicate.value

        return when (predicate.operator) {
            "eq" -> compareEquality(featureVal, targetElem)
            "ne" -> !compareEquality(featureVal, targetElem)
            "gt" -> compareNumeric(featureVal, targetElem) { a, b -> a > b }
            "gte" -> compareNumeric(featureVal, targetElem) { a, b -> a >= b }
            "lt" -> compareNumeric(featureVal, targetElem) { a, b -> a < b }
            "lte" -> compareNumeric(featureVal, targetElem) { a, b -> a <= b }
            "contains" -> {
                if (targetElem is JsonPrimitive && targetElem.isString && featureVal is String) {
                    featureVal.contains(targetElem.content, ignoreCase = false)
                } else if (featureVal is Collection<*>) {
                    val targetStr = if (targetElem is JsonPrimitive) targetElem.content else targetElem.toString()
                    featureVal.any { it?.toString() == targetStr }
                } else {
                    false
                }
            }
            "in" -> {
                if (targetElem is JsonArray) {
                    targetElem.any { elem -> compareEquality(featureVal, elem) }
                } else if (targetElem is JsonPrimitive && targetElem.isString && featureVal is String) {
                    targetElem.content.contains(featureVal)
                } else {
                    false
                }
            }
            "matches_regex" -> {
                if (featureVal is String && targetElem is JsonPrimitive && targetElem.isString) {
                    try {
                        Regex(targetElem.content).containsMatchIn(featureVal)
                    } catch (_: Exception) {
                        false
                    }
                } else {
                    false
                }
            }
            else -> false
        }
    }

    private fun compareEquality(featureVal: Any, elem: JsonElement): Boolean {
        if (elem !is JsonPrimitive) return false
        return when (featureVal) {
            is Boolean -> elem.booleanOrNull == featureVal
            is Number -> {
                val num = elem.doubleOrNull ?: elem.longOrNull?.toDouble()
                num != null && num == featureVal.toDouble()
            }
            is String -> elem.content == featureVal
            else -> elem.content == featureVal.toString()
        }
    }

    private fun compareNumeric(
        featureVal: Any,
        elem: JsonElement,
        op: (Double, Double) -> Boolean
    ): Boolean {
        if (featureVal !is Number || elem !is JsonPrimitive) return false
        val target = elem.doubleOrNull ?: elem.longOrNull?.toDouble() ?: return false
        return op(featureVal.toDouble(), target)
    }
}

