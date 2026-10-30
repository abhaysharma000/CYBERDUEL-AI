package ai.cyberduel.mobile

import ai.cyberduel.mobile.data.model.Decision
import ai.cyberduel.mobile.data.model.DeclarativeRule
import ai.cyberduel.mobile.data.model.RulePredicate
import ai.cyberduel.mobile.data.model.ThreatSeverity
import ai.cyberduel.mobile.domain.engine.DeclarativeRuleEvaluator
import ai.cyberduel.mobile.domain.engine.FeatureExtractor
import ai.cyberduel.mobile.domain.engine.HeuristicAnalyzer
import ai.cyberduel.mobile.domain.engine.URLNormalizer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HeuristicsAndRulesTest {

    @Test
    fun testBrandImpersonationFeatureAndHeuristic() {
        val norm = URLNormalizer.normalize("http://paypal-security-update.com.suspicious-domain.tk/login")
        val features = FeatureExtractor.extract(norm)

        assertTrue("Brand token detected should be true for paypal on unofficial domain", features.brandTokenDetected)
        assertTrue("Subdomain count should be >= 2", features.subdomainCount >= 2)

        val heuristic = HeuristicAnalyzer.analyze(features)
        assertTrue("Heuristic score should be elevated", heuristic.score >= 0.65)
        assertTrue("Evidence should contain HEUR-BRAND-IMPERSONATION", heuristic.evidence.any { it.ruleId == "HEUR-BRAND-IMPERSONATION" })
    }

    @Test
    fun testTrustedDomainWhitelistBypass() {
        val norm = URLNormalizer.normalize("https://accounts.google.com/signin/v2/identifier")
        val features = FeatureExtractor.extract(norm)

        assertTrue("google.com should be whitelisted", features.isWhitelisted)

        val heuristic = HeuristicAnalyzer.analyze(features)
        assertEquals(0.0, heuristic.score, 0.001)
        assertTrue("Evidence should contain HEUR-WHITELIST-TOP-DOMAIN", heuristic.evidence.any { it.ruleId == "HEUR-WHITELIST-TOP-DOMAIN" })
    }

    @Test
    fun testDeclarativeRuleEvaluatorEq() {
        val norm = URLNormalizer.normalize("https://admin:secret@portal.com/auth")
        val features = FeatureExtractor.extract(norm)

        val rule = DeclarativeRule(
            ruleId = "RULE-CRED-DETECTED",
            name = "Credentials Test",
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
        )

        val outcome = DeclarativeRuleEvaluator.evaluateRule(rule, features)
        assertNotNull("Rule must match when has_embedded_credentials is true", outcome)
        assertEquals(Decision.BLOCK, outcome?.action)
        assertEquals(0.95, outcome?.weight ?: 0.0, 0.001)
    }

    @Test
    fun testDeclarativeRuleEvaluatorRegexAndIn() {
        val norm = URLNormalizer.normalize("https://example.com/api/v1/update")
        val features = FeatureExtractor.extract(norm)

        val ruleRegex = DeclarativeRule(
            ruleId = "RULE-API-REGEX",
            name = "Regex API Test",
            severity = ThreatSeverity.MEDIUM,
            action = Decision.WARN,
            predicates = listOf(
                RulePredicate(
                    field = "scheme",
                    operator = "in",
                    value = JsonArray(listOf(JsonPrimitive("http"), JsonPrimitive("https")))
                )
            ),
            weight = 0.40
        )

        val outcome = DeclarativeRuleEvaluator.evaluateRule(ruleRegex, features)
        assertNotNull("Rule must match scheme in ['http', 'https']", outcome)
    }

    @Test
    fun testDeclarativeRuleEvaluatorMismatchReturnsNull() {
        val norm = URLNormalizer.normalize("https://example.com/index.html")
        val features = FeatureExtractor.extract(norm)

        val rule = DeclarativeRule(
            ruleId = "RULE-IP-CHECK",
            name = "IP Check",
            severity = ThreatSeverity.HIGH,
            action = Decision.WARN,
            predicates = listOf(
                RulePredicate(
                    field = "is_ip_literal",
                    operator = "eq",
                    value = JsonPrimitive(true)
                )
            ),
            weight = 0.70
        )

        val outcome = DeclarativeRuleEvaluator.evaluateRule(rule, features)
        assertNull("Rule should not match for non-IP host", outcome)
    }
}

