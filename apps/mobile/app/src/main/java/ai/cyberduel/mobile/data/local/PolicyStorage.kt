package ai.cyberduel.mobile.data.local

import android.content.Context
import ai.cyberduel.mobile.data.model.PolicyBundle
import ai.cyberduel.mobile.data.model.ReleaseManifest
import ai.cyberduel.mobile.data.model.TrustAnchorSet
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File

class PolicyStorage(private val context: Context) {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        prettyPrint = false
    }

    private val activePolicyFile get() = File(context.filesDir, "active_policy.json")
    private val backupPolicyFile get() = File(context.filesDir, "backup_policy.json")
    private val activeManifestFile get() = File(context.filesDir, "active_manifest.json")
    private val trustAnchorsFile get() = File(context.filesDir, "trust_anchors.json")

    @Synchronized
    fun getActivePolicy(): PolicyBundle {
        return try {
            if (activePolicyFile.exists()) {
                val content = activePolicyFile.readText()
                json.decodeFromString<PolicyBundle>(content)
            } else {
                FactoryDefaults.FACTORY_POLICY_BUNDLE
            }
        } catch (_: Exception) {
            FactoryDefaults.FACTORY_POLICY_BUNDLE
        }
    }

    @Synchronized
    fun getBackupPolicy(): PolicyBundle? {
        return try {
            if (backupPolicyFile.exists()) {
                val content = backupPolicyFile.readText()
                json.decodeFromString<PolicyBundle>(content)
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    @Synchronized
    fun getActiveManifest(): ReleaseManifest? {
        return try {
            if (activeManifestFile.exists()) {
                val content = activeManifestFile.readText()
                json.decodeFromString<ReleaseManifest>(content)
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    @Synchronized
    fun getTrustAnchors(): TrustAnchorSet {
        return try {
            if (trustAnchorsFile.exists()) {
                val content = trustAnchorsFile.readText()
                json.decodeFromString<TrustAnchorSet>(content)
            } else {
                FactoryDefaults.FACTORY_TRUST_ANCHORS
            }
        } catch (_: Exception) {
            FactoryDefaults.FACTORY_TRUST_ANCHORS
        }
    }

    @Synchronized
    fun saveActivePolicy(newPolicy: PolicyBundle, manifest: ReleaseManifest? = null) {
        // Backup current active policy if it exists
        if (activePolicyFile.exists()) {
            try {
                val currentText = activePolicyFile.readText()
                val tempBackup = File(context.filesDir, "backup_policy.tmp")
                tempBackup.writeText(currentText)
                tempBackup.renameTo(backupPolicyFile)
            } catch (_: Exception) {
                // Best effort backup
            }
        }

        // Atomically write new active policy
        val tempActive = File(context.filesDir, "active_policy.tmp")
        tempActive.writeText(json.encodeToString(newPolicy))
        tempActive.renameTo(activePolicyFile)

        if (manifest != null) {
            val tempManifest = File(context.filesDir, "active_manifest.tmp")
            tempManifest.writeText(json.encodeToString(manifest))
            tempManifest.renameTo(activeManifestFile)
        }
    }

    @Synchronized
    fun saveTrustAnchors(anchors: TrustAnchorSet) {
        val tempAnchors = File(context.filesDir, "trust_anchors.tmp")
        tempAnchors.writeText(json.encodeToString(anchors))
        tempAnchors.renameTo(trustAnchorsFile)
    }

    @Synchronized
    fun canRollback(): Boolean {
        return backupPolicyFile.exists()
    }

    @Synchronized
    fun rollback(): PolicyBundle? {
        if (!backupPolicyFile.exists()) return null
        return try {
            val backupText = backupPolicyFile.readText()
            val backupPolicy = json.decodeFromString<PolicyBundle>(backupText)

            // Swap backup to active
            val tempActive = File(context.filesDir, "active_policy.tmp")
            tempActive.writeText(backupText)
            tempActive.renameTo(activePolicyFile)

            // Delete old backup to prevent cyclic rollbacks
            backupPolicyFile.delete()
            activeManifestFile.delete()

            backupPolicy
        } catch (_: Exception) {
            null
        }
    }

    @Synchronized
    fun resetToFactoryDefaults() {
        activePolicyFile.delete()
        backupPolicyFile.delete()
        activeManifestFile.delete()
        trustAnchorsFile.delete()
    }
}

