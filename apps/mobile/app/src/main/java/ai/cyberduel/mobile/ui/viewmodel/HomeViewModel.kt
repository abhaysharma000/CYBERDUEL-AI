package ai.cyberduel.mobile.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ai.cyberduel.mobile.CyberDuelApp
import ai.cyberduel.mobile.data.local.HistoryEntry
import ai.cyberduel.mobile.data.model.Decision
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class HomeUiState(
    val isProtectionEnabled: Boolean = true,
    val policyVersion: String = "2026.10.1",
    val sequenceNumber: Long = 1L,
    val totalScans: Int = 0,
    val threatsBlocked: Int = 0,
    val suspiciousWarned: Int = 0,
    val recentScans: List<HistoryEntry> = emptyList()
)

class HomeViewModel : ViewModel() {

    private val app = CyberDuelApp.instance
    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    init {
        loadState()
    }

    fun loadState() {
        val policy = app.threatEngine.getPolicy()
        val history = app.settingsRepository.getHistory()
        val blockedCount = history.count { it.decision == Decision.BLOCK }
        val warnedCount = history.count { it.decision == Decision.WARN }

        _uiState.value = HomeUiState(
            isProtectionEnabled = app.settingsRepository.isProtectionEnabled,
            policyVersion = policy.policyVersion,
            sequenceNumber = policy.sequenceNumber,
            totalScans = history.size,
            threatsBlocked = blockedCount,
            suspiciousWarned = warnedCount,
            recentScans = history.take(5)
        )
    }

    fun toggleProtection(enabled: Boolean) {
        app.settingsRepository.isProtectionEnabled = enabled
        _uiState.value = _uiState.value.copy(isProtectionEnabled = enabled)
    }
}

