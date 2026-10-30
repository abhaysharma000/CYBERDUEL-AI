package ai.cyberduel.mobile

import android.app.Application
import ai.cyberduel.mobile.data.local.PolicyStorage
import ai.cyberduel.mobile.data.local.SettingsRepository
import ai.cyberduel.mobile.data.remote.ApiClient
import ai.cyberduel.mobile.domain.engine.LocalThreatEngine
import ai.cyberduel.mobile.domain.updates.MobileUpdateManager

class CyberDuelApp : Application() {

    lateinit var settingsRepository: SettingsRepository
        private set

    lateinit var policyStorage: PolicyStorage
        private set

    lateinit var threatEngine: LocalThreatEngine
        private set

    lateinit var apiClient: ApiClient
        private set

    lateinit var updateManager: MobileUpdateManager
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        settingsRepository = SettingsRepository(this)
        policyStorage = PolicyStorage(this)
        val initialPolicy = policyStorage.getActivePolicy()
        threatEngine = LocalThreatEngine(initialPolicy)
        apiClient = ApiClient(settingsRepository.backendUrl)
        updateManager = MobileUpdateManager(
            apiClient = apiClient,
            policyStorage = policyStorage,
            threatEngine = threatEngine,
            settingsRepository = settingsRepository
        )
    }

    companion object {
        lateinit var instance: CyberDuelApp
            private set
    }
}

