package ai.cyberduel.mobile.ui.viewmodel

import androidx.lifecycle.ViewModel
import ai.cyberduel.mobile.CyberDuelApp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class SettingsUiState(
    val isProtectionEnabled: Boolean = true,
    val isTelemetryEnabled: Boolean = true,
    val backendUrl: String = "",
    val clientId: String = "",
    val historyCount: Int = 0
)

class SettingsViewModel : ViewModel() {

    private val app = CyberDuelApp.instance
    private val _uiState = MutableStateFlow(SettingsUiState())
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    init {
        loadSettings()
    }

    fun loadSettings() {
        val repo = app.settingsRepository
        _uiState.value = SettingsUiState(
            isProtectionEnabled = repo.isProtectionEnabled,
            isTelemetryEnabled = repo.isTelemetryEnabled,
            backendUrl = repo.backendUrl,
            clientId = repo.clientId,
            historyCount = repo.getHistory().size
        )
    }

    fun setProtectionEnabled(enabled: Boolean) {
        app.settingsRepository.isProtectionEnabled = enabled
        _uiState.value = _uiState.value.copy(isProtectionEnabled = enabled)
    }

    fun setTelemetryEnabled(enabled: Boolean) {
        app.settingsRepository.isTelemetryEnabled = enabled
        _uiState.value = _uiState.value.copy(isTelemetryEnabled = enabled)
    }

    fun setBackendUrl(url: String) {
        app.settingsRepository.backendUrl = url
        app.apiClient.setBaseUrl(url)
        _uiState.value = _uiState.value.copy(backendUrl = url)
    }

    fun clearHistory() {
        app.settingsRepository.clearHistory()
        _uiState.value = _uiState.value.copy(historyCount = 0)
    }
}

