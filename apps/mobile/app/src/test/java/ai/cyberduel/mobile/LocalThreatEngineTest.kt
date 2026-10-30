package ai.cyberduel.mobile

import ai.cyberduel.mobile.data.local.FactoryDefaults
import ai.cyberduel.mobile.data.model.Decision
import ai.cyberduel.mobile.data.model.ProvenanceType
import ai.cyberduel.mobile.domain.engine.LocalThreatEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class LocalThreatEngineTest {

    private lateinit var engine: LocalThreatEngine

    @Before
    fun setUp() {
        engine = LocalThreatEngine(FactoryDefaults.FACTORY_POLICY_BUNDLE)
    }

    @Test
    fun testExactThreatIndicatorMatch() {
        val rawUrl = "https://malicious-phish-portal.test/steal-creds"
        val result = engine.evaluate(rawUrl)

        assertEquals(Decision.BLOCK, result.decision)
        assertEquals(1.0, result.riskScore, 0.001)
        assertEquals(0.99, result.confidence, 0.001)
        assertEquals(ProvenanceType.THREAT_INTELLIGENCE, result.provenance)
        assertTrue(result.matchedRules.contains("IND-MALICIOUS-TEST-DOMAIN"))
    }

    @Test
    fun testDeclarativeRuleMatchEmbeddedCredentials() {
        val rawUrl = "https://victim:secret@evil-server.org/dashboard"
        val result = engine.evaluate(rawUrl)

        assertEquals(Decision.BLOCK, result.decision)
        assertTrue("Risk score should be >= 0.85", result.riskScore >= 0.85)
        assertEquals(ProvenanceType.RULE_ENGINE, result.provenance)
        assertTrue(result.matchedRules.contains("RULE-EMBEDDED-CREDENTIALS"))
    }

    @Test
    fun testHeuristicBrandMimicryWarning() {
        val rawUrl = "https://paypal-security-verification.randomsite.com/login"
        val result = engine.evaluate(rawUrl)

        assertTrue("Decision should be WARN or BLOCK", result.decision == Decision.WARN || result.decision == Decision.BLOCK)
        assertTrue("Risk score should be elevated", result.riskScore >= 0.50)
    }

    @Test
    fun testBenignTrustedDomainAllows() {
        val rawUrl = "https://google.com/search?q=cybersecurity"
        val result = engine.evaluate(rawUrl)

        assertEquals(Decision.ALLOW, result.decision)
        assertTrue("Risk score should be low", result.riskScore < 0.20)
    }

    @Test
    fun testInvalidOrUnsupportedSchemeDoesNotCrash() {
        val rawUrl = "about:blank"
        val result = engine.evaluate(rawUrl)

        assertEquals(Decision.ALLOW, result.decision)
        assertEquals(0.0, result.riskScore, 0.001)
    }
}

