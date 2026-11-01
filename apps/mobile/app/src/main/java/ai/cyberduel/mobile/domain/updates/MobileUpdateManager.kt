package ai.cyberduel.mobile.domain.updates

import ai.cyberduel.mobile.data.local.PolicyStorage
import ai.cyberduel.mobile.data.local.SettingsRepository
import ai.cyberduel.mobile.data.model.ReleaseManifest
import ai.cyberduel.mobile.data.model.UpdateAcknowledgement
import ai.cyberduel.mobile.data.model.UpdateCheckRequest
import ai.cyberduel.mobile.data.remote.ApiClient
import ai.cyberduel.mobile.domain.crypto.ClientUpdateVerifier
import ai.cyberduel.mobile.domain.engine.LocalThreatEngine
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.UUID

sealed class UpdateState {
    object Idle : UpdateState()
    object Checking : UpdateState()
    data class Available(val manifest: ReleaseManifest) : UpdateState()
    object Downloading : UpdateState()
    object Verifying : UpdateState()
    data class Installed(val version: String, val sequence: Long) : UpdateState()
    data class Failed(val error: String, val step: String? = null) : UpdateState()
    object RolledBack : UpdateState()
}

class MobileUpdateManager(
    private val apiClient: ApiClient,
    private val policyStorage: PolicyStorage,
    private val threatEngine: LocalThreatEngine,
    private val settingsRepository: SettingsRepository,
    private val clientVersion: String = "1.0.0",
    private val engineVersion: String = "1.0.0"
) {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val _updateState = MutableStateFlow<UpdateState>(UpdateState.Idle)
    val updateState: StateFlow<UpdateState> = _updateState.asStateFlow()

    suspend fun checkAndApplyUpdate(): Boolean {
        _updateState.value = UpdateState.Checking
        val activePolicy = policyStorage.getActivePolicy()
        settingsRepository.lastUpdateCheckTimestamp = System.currentTimeMillis()

        val checkRequest = UpdateCheckRequest(
            clientId = settingsRepository.clientId,
            clientType = "mobile_app",
            engineVersion = engineVersion,
            currentPolicyVersion = activePolicy.policyVersion,
            currentSequenceNumber = activePolicy.sequenceNumber,
            channel = settingsRepository.releaseChannel,
            platform = "Android-15"
        )

        val checkResponse = try {
            apiClient.checkForUpdates(checkRequest)
        } catch (e: Exception) {
            _updateState.value = UpdateState.Failed("Update check network error: ${e.message}")
            return false
        }

        if (!checkResponse.updateAvailable || checkResponse.latestVersion == null) {
            _updateState.value = UpdateState.Idle
            return false
        }

        _updateState.value = UpdateState.Downloading
        val manifest = try {
            apiClient.fetchManifest(checkResponse.latestVersion)
        } catch (e: Exception) {
            val err = "Failed to download manifest: ${e.message}"
            _updateState.value = UpdateState.Failed(err)
            return false
        }

        _updateState.value = UpdateState.Available(manifest)
        return applyUpdate(manifest)
    }

    suspend fun applyUpdate(manifest: ReleaseManifest): Boolean {
        _updateState.value = UpdateState.Downloading
        val activePolicy = policyStorage.getActivePolicy()

        val (rawArtifactJson, bundle) = try {
            apiClient.fetchArtifact(manifest.artifactDigest)
        } catch (e: Exception) {
            val err = "Failed to download update bundle: ${e.message}"
            _updateState.value = UpdateState.Failed(err)
            sendAck(manifest, success = false, error = err)
            return false
        }

        _updateState.value = UpdateState.Verifying
        val trustAnchors = policyStorage.getTrustAnchors()
        val manifestJson = json.encodeToString(manifest)
        val artifactBytes = rawArtifactJson.toByteArray(StandardCharsets.UTF_8)

        val verifier = ClientUpdateVerifier(
            currentSequence = activePolicy.sequenceNumber,
            currentPolicyVersion = activePolicy.policyVersion,
            clientVersion = clientVersion,
            engineVersion = engineVersion
        )

        val result = verifier.verify(
            manifest = manifest,
            manifestRawJson = manifestJson,
            artifactRawBytes = artifactBytes,
            bundle = bundle,
            trustAnchors = trustAnchors
        )

        if (!result.isValid) {
            val err = result.errorMessage ?: "Verification failed"
            _updateState.value = UpdateState.Failed(err, result.stepFailed)
            sendAck(manifest, success = false, error = "${result.stepFailed}: $err")
            return false
        }

        // Verification passed: Install atomically
        policyStorage.saveActivePolicy(bundle, manifest)
        threatEngine.updatePolicy(bundle)

        _updateState.value = UpdateState.Installed(bundle.policyVersion, bundle.sequenceNumber)
        sendAck(manifest, success = true)
        return true
    }

    fun canRollback(): Boolean = policyStorage.canRollback()

    fun rollback(): Boolean {
        val backupPolicy = policyStorage.rollback() ?: return false
        threatEngine.updatePolicy(backupPolicy)
        _updateState.value = UpdateState.RolledBack
        return true
    }

    fun resetToFactory() {
        policyStorage.resetToFactoryDefaults()
        threatEngine.updatePolicy(policyStorage.getActivePolicy())
        _updateState.value = UpdateState.Idle
    }

    private suspend fun sendAck(manifest: ReleaseManifest, success: Boolean, error: String? = null) {
        val ack = UpdateAcknowledgement(
            acknowledgementId = "ack-${UUID.randomUUID().toString().take(8)}",
            clientId = settingsRepository.clientId,
            releaseId = manifest.releaseId,
            policyVersion = manifest.policyVersion,
            sequenceNumber = manifest.sequenceNumber,
            status = if (success) {
                if (manifest.isRollback) "rolled_back" else "installed"
            } else "failed",
            errorMessage = error,
            isRollbackApplied = manifest.isRollback,
            channel = manifest.channel,
            reportedAt = Instant.now().toString()
        )
        apiClient.sendAcknowledgement(ack)
    }
}
