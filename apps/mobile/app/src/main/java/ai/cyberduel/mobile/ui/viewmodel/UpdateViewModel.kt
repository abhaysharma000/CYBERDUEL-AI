package ai.cyberduel.mobile.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ai.cyberduel.mobile.CyberDuelApp
import ai.cyberduel.mobile.data.model.ReleaseChannel
import ai.cyberduel.mobile.domain.updates.UpdateState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class UpdateUiState(
    val activePolicyVersion: String = "",
    val sequenceNumber: Long = 1L,
    val canRollback: Boolean = false,
    val releaseChannel: ReleaseChannel = ReleaseChannel.STABLE,
    val lastCheckTimeFormatted: String = "Never",
    val updateState: UpdateState = UpdateState.Idle,
    val statusMessage: String? = null
)

class UpdateViewModel : ViewModel() {

    private val app = CyberDuelApp.instance
    private val _uiState = MutableStateFlow(UpdateUiState())
    val uiState: StateFlow<UpdateUiState> = _uiState.asStateFlow()

    init {
        refreshState()
        viewModelScope.launch {
            app.updateManager.updateState.collect { state ->
                val msg = when (state) {
                    is UpdateState.Checking -> "Checking release authority..."
                    is UpdateState.Downloading -> "Downloading policy bundle..."
                    is UpdateState.Verifying -> "Running 7-step cryptographic verification..."
                    is UpdateState.Installed -> "Successfully verified & installed version ${state.version} (seq ${state.sequence})!"
                    is UpdateState.Failed -> "Update verification failed: ${state.error}"
                    is UpdateState.RolledBack -> "Successfully rolled back to previous policy bundle."
                    else -> null
                }
                refreshState(state, msg)
            }
        }
    }

    fun refreshState(
        updateState: UpdateState = app.updateManager.updateState.value,
        statusMessage: String? = null
    ) {
        val policy = app.threatEngine.getPolicy()
        val lastCheck = app.settingsRepository.lastUpdateCheckTimestamp
        val formattedTime = if (lastCheck > 0) {
            java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault())
                .format(java.util.Date(lastCheck))
        } else {
            "Never"
        }

        _uiState.value = UpdateUiState(
            activePolicyVersion = policy.policyVersion,
            sequenceNumber = policy.sequenceNumber,
            canRollback = app.updateManager.canRollback(),
            releaseChannel = app.settingsRepository.releaseChannel,
            lastCheckTimeFormatted = formattedTime,
            updateState = updateState,
            statusMessage = statusMessage
        )
    }

    fun checkForUpdates() {
        viewModelScope.launch {
            app.updateManager.checkAndApplyUpdate()
            refreshState()
        }
    }

    fun rollback() {
        if (app.updateManager.rollback()) {
            refreshState(UpdateState.RolledBack, "Rolled back to previous verified policy.")
        }
    }

    fun resetToFactory() {
        app.updateManager.resetToFactory()
        refreshState(UpdateState.Idle, "Reset to offline factory default policy.")
    }

    fun setReleaseChannel(channel: ReleaseChannel) {
        app.settingsRepository.releaseChannel = channel
        refreshState()
    }
}

