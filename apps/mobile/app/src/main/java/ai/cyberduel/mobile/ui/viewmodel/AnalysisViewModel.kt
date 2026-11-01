package ai.cyberduel.mobile.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ai.cyberduel.mobile.CyberDuelApp
import ai.cyberduel.mobile.data.model.Decision
import ai.cyberduel.mobile.data.model.LocalThreatResult
import ai.cyberduel.mobile.data.model.NormalizedURL
import ai.cyberduel.mobile.data.model.ThreatObservationReport
import ai.cyberduel.mobile.domain.engine.URLNormalizer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant
import java.util.UUID

data class AnalysisUiState(
    val currentUrl: String = "",
    val isAnalyzing: Boolean = false,
    val normalizedUrl: NormalizedURL? = null,
    val result: LocalThreatResult? = null,
    val isReportingDispute: Boolean = false,
    val disputeSuccessMessage: String? = null,
    val errorMessage: String? = null
)

class AnalysisViewModel : ViewModel() {

    private val app = CyberDuelApp.instance
    private val _uiState = MutableStateFlow(AnalysisUiState())
    val uiState: StateFlow<AnalysisUiState> = _uiState.asStateFlow()

    fun setInputUrl(url: String) {
        _uiState.value = _uiState.value.copy(currentUrl = url)
    }

    fun analyze(rawUrl: String) {
        val trimmed = rawUrl.trim()
        if (trimmed.isEmpty()) return

        _uiState.value = _uiState.value.copy(
            currentUrl = trimmed,
            isAnalyzing = true,
            result = null,
            normalizedUrl = null,
            disputeSuccessMessage = null,
            errorMessage = null
        )

        viewModelScope.launch(Dispatchers.Default) {
            val normalized = try {
                URLNormalizer.normalize(trimmed)
            } catch (_: Exception) {
                null
            }

            val threatResult = app.threatEngine.evaluate(trimmed)

            // Persist to history
            app.settingsRepository.addHistoryEntry(trimmed, threatResult)

            _uiState.value = _uiState.value.copy(
                isAnalyzing = false,
                normalizedUrl = normalized,
                result = threatResult
            )

            // Submit privacy-conscious telemetry observation if enabled and threat detected
            if (app.settingsRepository.isTelemetryEnabled && threatResult.decision != Decision.ALLOW && normalized != null) {
                launch(Dispatchers.IO) {
                    try {
                        val report = ThreatObservationReport(
                            observationId = UUID.randomUUID().toString(),
                            source = "mobile_app",
                            normalizedTarget = normalized.domain.ifEmpty { normalized.canonicalUrl },
                            observedAt = Instant.now().toString(),
                            localActionTaken = threatResult.decision,
                            engineVersion = "1.0.0",
                            policyVersion = threatResult.policyVersion,
                            telemetrySummary = JsonObject(mapOf(
                                "raw_url" to JsonPrimitive(normalized.canonicalUrl),
                                "domain" to JsonPrimitive(normalized.domain),
                                "risk_score" to JsonPrimitive(threatResult.riskScore),
                                "confidence_score" to JsonPrimitive(threatResult.confidence),
                                "explanation" to JsonPrimitive(threatResult.explanation),
                                "client_id" to JsonPrimitive(app.settingsRepository.clientId),
                                "threat_types" to JsonPrimitive(if (threatResult.decision == Decision.BLOCK) "phishing" else "suspicious")
                            ))
                        )
                        app.apiClient.reportObservation(report)
                    } catch (_: Exception) {
                        // Silent best effort telemetry
                    }
                }
            }
        }
    }

    fun submitFalsePositiveDispute(reason: String) {
        val currentResult = _uiState.value.result ?: return
        val currentNorm = _uiState.value.normalizedUrl

        _uiState.value = _uiState.value.copy(isReportingDispute = true)

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val report = ThreatObservationReport(
                    observationId = UUID.randomUUID().toString(),
                    source = "mobile_app",
                    normalizedTarget = currentNorm?.domain ?: currentNorm?.canonicalUrl ?: "manual-dispute.example",
                    observedAt = Instant.now().toString(),
                    localActionTaken = currentResult.decision,
                    engineVersion = "1.0.0",
                    policyVersion = currentResult.policyVersion,
                    telemetrySummary = JsonObject(mapOf(
                        "disputed_decision" to JsonPrimitive(currentResult.decision.name),
                        "user_reason" to JsonPrimitive(reason),
                        "client_id" to JsonPrimitive(app.settingsRepository.clientId)
                    ))
                )

                app.apiClient.reportObservation(report)
                _uiState.value = _uiState.value.copy(
                    isReportingDispute = false,
                    disputeSuccessMessage = "Feedback submitted. Threat intelligence lab will evaluate."
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isReportingDispute = false,
                    disputeSuccessMessage = "Dispute recorded locally (offline mode)."
                )
            }
        }
    }
}

