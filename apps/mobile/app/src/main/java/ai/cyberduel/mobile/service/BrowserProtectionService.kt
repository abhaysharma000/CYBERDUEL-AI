package ai.cyberduel.mobile.service

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityManager
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.app.NotificationCompat
import ai.cyberduel.mobile.CyberDuelApp
import ai.cyberduel.mobile.MainActivity
import ai.cyberduel.mobile.R
import ai.cyberduel.mobile.data.model.Decision
import ai.cyberduel.mobile.data.model.ThreatObservationReport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant
import java.util.UUID

class BrowserProtectionService : AccessibilityService() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var lastInspectedUrl: String? = null
    private val recentEvaluations = LinkedHashSet<String>()

    override fun onServiceConnected() {
        super.onServiceConnected()
        Log.i(TAG, "CyberDuel AI Browser Protection Service connected and active")
        createNotificationChannel()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        val app = CyberDuelApp.instance
        if (!app.settingsRepository.isProtectionEnabled) return

        val rootNode = rootInActiveWindow ?: return
        val extractedUrl = findUrlInNode(rootNode) ?: return

        val cleanUrl = normalizeCandidateUrl(extractedUrl) ?: return

        // Prevent redundant evaluations on unchanged URL
        if (cleanUrl == lastInspectedUrl || recentEvaluations.contains(cleanUrl)) {
            return
        }

        lastInspectedUrl = cleanUrl
        if (recentEvaluations.size > 200) {
            recentEvaluations.clear()
        }
        recentEvaluations.add(cleanUrl)

        // Evaluate with LocalThreatEngine
        val threatResult = app.threatEngine.evaluate(cleanUrl)
        app.settingsRepository.addHistoryEntry(cleanUrl, threatResult)

        if (threatResult.decision == Decision.BLOCK || threatResult.decision == Decision.WARN) {
            Log.w(TAG, "THREAT DETECTED IN BROWSER: $cleanUrl | Decision: ${threatResult.decision}")

            // 1. Kick browser off the dangerous site
            performGlobalAction(GLOBAL_ACTION_BACK)

            // 2. Bring CyberDuel Warning Shield to foreground
            val blockIntent = Intent(this, MainActivity::class.java).apply {
                action = ACTION_THREAT_BLOCKED
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra(EXTRA_BLOCKED_URL, cleanUrl)
                putExtra(EXTRA_DECISION, threatResult.decision.name)
                putExtra(EXTRA_REASON, threatResult.explanation)
                putExtra(EXTRA_SCORE, threatResult.riskScore)
            }
            startActivity(blockIntent)

            // 3. Post urgent Heads-Up notification
            showThreatNotification(cleanUrl, threatResult.decision, threatResult.explanation)

            // 4. Stream telemetry to Render Docker laboratory
            if (app.settingsRepository.isTelemetryEnabled) {
                serviceScope.launch {
                    try {
                        val report = ThreatObservationReport(
                            observationId = UUID.randomUUID().toString(),
                            source = "mobile_app",
                            normalizedTarget = cleanUrl,
                            observedAt = Instant.now().toString(),
                            localActionTaken = threatResult.decision,
                            engineVersion = "1.0.0",
                            policyVersion = threatResult.policyVersion,
                            telemetrySummary = JsonObject(mapOf(
                                "raw_url" to JsonPrimitive(cleanUrl),
                                "risk_score" to JsonPrimitive(threatResult.riskScore),
                                "explanation" to JsonPrimitive(threatResult.explanation),
                                "client_id" to JsonPrimitive(app.settingsRepository.clientId),
                                "source_event" to JsonPrimitive("accessibility_browser_guard")
                            ))
                        )
                        app.apiClient.reportObservation(report)
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to stream threat observation to Render: ${e.message}")
                    }
                }
            }
        }
    }

    override fun onInterrupt() {
        Log.i(TAG, "Browser Protection Service interrupted")
    }

    private fun findUrlInNode(node: AccessibilityNodeInfo): String? {
        val viewId = node.viewIdResourceName?.lowercase() ?: ""
        val text = node.text?.toString()?.trim()

        if (viewId.contains("url_bar") || viewId.contains("location_bar") || viewId.contains("address_bar")) {
            if (!text.isNullOrEmpty() && (text.contains(".") || text.startsWith("http"))) {
                return text
            }
        }

        // Recursively inspect children
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val found = findUrlInNode(child)
            child.recycle()
            if (found != null) return found
        }
        return null
    }

    private fun normalizeCandidateUrl(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty() || trimmed.contains(" ") || !trimmed.contains(".")) {
            return null
        }
        return if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            trimmed
        } else {
            "https://$trimmed"
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "CyberDuel AI Web Shield",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Urgent alerts when malicious links are intercepted in phone browsers"
                enableVibration(true)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun showThreatNotification(url: String, decision: Decision, reason: String) {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield_foreground)
            .setContentTitle("🛡️ CyberDuel AI: ${decision.name} Action Taken")
            .setContentText("Blocked harmful URL in browser: $url")
            .setStyle(NotificationCompat.BigTextStyle().bigText("CyberDuel AI intercepted and blocked harmful navigation:\n$url\n\nReason: $reason"))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, notification)
    }

    companion object {
        const val TAG = "BrowserGuardService"
        const val CHANNEL_ID = "cyberduel_threat_alerts"
        const val NOTIFICATION_ID = 202610

        const val ACTION_THREAT_BLOCKED = "ai.cyberduel.mobile.ACTION_THREAT_BLOCKED"
        const val EXTRA_BLOCKED_URL = "extra_blocked_url"
        const val EXTRA_DECISION = "extra_decision"
        const val EXTRA_REASON = "extra_reason"
        const val EXTRA_SCORE = "extra_score"

        fun isServiceRunning(context: Context): Boolean {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager ?: return false
            val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            for (service in enabledServices) {
                val serviceInfo = service.resolveInfo.serviceInfo
                if (serviceInfo.packageName == context.packageName && serviceInfo.name == BrowserProtectionService::class.java.name) {
                    return true
                }
            }
            return false
        }
    }
}

