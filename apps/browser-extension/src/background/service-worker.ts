/**
 * CyberDuel AI — Background Service Worker (Manifest V3)
 * Core coordinator for local threat decisions, DNR rules, periodic update alarms, and messaging.
 */

import { LocalThreatEngine } from '../engine/threat-decision';
import { PolicyStore } from '../storage/policy-store';
import { SettingsStore } from '../storage/settings-store';
import { UpdateManager } from '../updates/update-manager';
import { TelemetryClient } from '../telemetry/telemetry-client';
import { DNRRuleManager } from '../dnr/rule-manager';
import { URLNormalizer } from '../engine/normalizer';
import { computeSha256 } from '../crypto/sha256';
import { ExtensionMessage, ProtectionStatusData } from '../types/messages';

let threatEngine: LocalThreatEngine | null = null;
const updateManager = new UpdateManager();

async function getThreatEngine(): Promise<LocalThreatEngine> {
  if (!threatEngine) {
    const state = await PolicyStore.getState();
    threatEngine = new LocalThreatEngine(state.active_policy);
  }
  return threatEngine;
}

// 1. Extension Lifecycle: Installation and Startup
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[CyberDuel AI] Extension installed/updated:', details.reason);
  const state = await PolicyStore.getState();
  threatEngine = new LocalThreatEngine(state.active_policy);

  // Install initial DNR rules
  try {
    await DNRRuleManager.installPolicyRules(state.active_policy);
  } catch (err) {
    console.warn('[CyberDuel AI] Initial DNR installation warning:', err);
  }

  // Schedule periodic update alarm
  const settings = await SettingsStore.getSettings();
  chrome.alarms.create('check_policy_updates', {
    periodInMinutes: settings.update_check_interval_minutes || 30,
  });
});

chrome.runtime.onStartup.addListener(async () => {
  const state = await PolicyStore.getState();
  threatEngine = new LocalThreatEngine(state.active_policy);
});

// 2. Scheduled Alarms (Background Updates)
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'check_policy_updates') {
    const settings = await SettingsStore.getSettings();
    if (settings.protection_enabled) {
      console.log('[CyberDuel AI] Executing scheduled policy update cycle...');
      const result = await updateManager.runUpdateCycle();
      if (result.success && result.newVersion) {
        const state = await PolicyStore.getState();
        if (threatEngine) {
          threatEngine.updatePolicy(state.active_policy);
        }
      }
    }
  }
});

// 3. Message Passing Router
chrome.runtime.onMessage.addListener((message: ExtensionMessage, sender, sendResponse) => {
  handleIncomingMessage(message, sender)
    .then((resp) => sendResponse(resp))
    .catch((err) => {
      console.error('[CyberDuel AI] Error handling message:', err);
      sendResponse({ error: String(err) });
    });
  return true; // Keep message channel open for async response
});

async function handleIncomingMessage(
  message: ExtensionMessage,
  _sender: chrome.runtime.MessageSender
): Promise<unknown> {
  if (!message || typeof message.type !== 'string') {
    return { error: 'Invalid message structure' };
  }

  const engine = await getThreatEngine();
  const settings = await SettingsStore.getSettings();

  switch (message.type) {
    case 'EVALUATE_URL_REQUEST': {
      if (!settings.protection_enabled) {
        return {
          type: 'EVALUATE_URL_RESPONSE',
          url: message.url,
          result: {
            decision: 'allow',
            risk_score: 0.0,
            confidence: 1.0,
            evidence: [],
            explanation: 'Protection is currently disabled by user preference.',
            policy_version: engine.getPolicyVersion(),
            matched_rules: [],
            provenance: 'heuristic',
            is_stale: false,
            evaluated_at: new Date().toISOString(),
          },
        };
      }

      const evalResult = engine.evaluate(message.url);

      // Record in recent evaluations ring buffer
      let canonicalUrl = message.url;
      try {
        const norm = URLNormalizer.normalize(message.url);
        canonicalUrl = norm.canonical_url;
        // Asynchronously report observation if suspicious or blocked
        if (evalResult.decision !== 'allow') {
          TelemetryClient.reportObservation(norm, evalResult, engine.getPolicyVersion()).catch(() => {});
        }
      } catch {
        // Suppress parsing error for ring buffer
      }

      await PolicyStore.addRecentEvaluation({
        url: message.url,
        canonical_url: canonicalUrl,
        decision: evalResult.decision,
        risk_score: evalResult.risk_score,
        explanation: evalResult.explanation,
        evaluated_at: evalResult.evaluated_at,
      });

      return {
        type: 'EVALUATE_URL_RESPONSE',
        url: message.url,
        result: evalResult,
      };
    }

    case 'GET_PROTECTION_STATUS_REQUEST': {
      const state = await PolicyStore.getState();
      let dnrCount = 0;
      if (chrome.declarativeNetRequest && chrome.declarativeNetRequest.getDynamicRules) {
        try {
          const rules = await chrome.declarativeNetRequest.getDynamicRules();
          dnrCount = rules.length;
        } catch {
          dnrCount = 0;
        }
      }

      const evals = await PolicyStore.getRecentEvaluations();

      const statusData: ProtectionStatusData = {
        isEnabled: settings.protection_enabled,
        policyVersion: state.active_policy.policy_version,
        sequenceNumber: state.sequence_number,
        lastUpdateCheckedAt: state.last_update_check_at || null,
        lastUpdatedInstalledAt: state.last_verified_at || null,
        isStale: new Date(state.active_policy.expires_at).getTime() < Date.now(),
        cloudConnected: true,
        activeDNRRuleCount: dnrCount,
        recentEvaluationsCount: evals.length,
        updateStatus: state.last_update_status || 'idle',
        lastErrorMessage: state.last_error_message || null,
      };

      return {
        type: 'GET_PROTECTION_STATUS_RESPONSE',
        status: statusData,
      };
    }

    case 'TRIGGER_UPDATE_CHECK_REQUEST': {
      const updateResult = await updateManager.runUpdateCycle();
      if (updateResult.success && updateResult.newVersion) {
        const state = await PolicyStore.getState();
        if (threatEngine) {
          threatEngine.updatePolicy(state.active_policy);
        }
      }
      return {
        type: 'TRIGGER_UPDATE_CHECK_RESPONSE',
        success: updateResult.success,
        message: updateResult.message,
        updatedVersion: updateResult.newVersion,
      };
    }

    case 'GET_SETTINGS_REQUEST': {
      return {
        type: 'GET_SETTINGS_RESPONSE',
        settings,
      };
    }

    case 'UPDATE_SETTINGS_REQUEST': {
      const updated = await SettingsStore.updateSettings(message.settings);
      return {
        type: 'UPDATE_SETTINGS_RESPONSE',
        success: true,
        settings: updated,
      };
    }

    case 'SUBMIT_FALSE_POSITIVE_REQUEST': {
      const state = await PolicyStore.getState();
      const success = await TelemetryClient.reportFalsePositive(
        message.targetUrl,
        message.reportedDecision,
        message.reason,
        state.active_policy.policy_version
      );
      return {
        type: 'SUBMIT_FALSE_POSITIVE_RESPONSE',
        success,
        message: success
          ? 'False positive observation recorded for laboratory triage.'
          : 'Failed to transmit report. Local protection remains active.',
      };
    }

    case 'CREATE_CONTINUATION_TOKEN_REQUEST': {
      const digest = computeSha256(message.targetUrl);
      const token = await PolicyStore.createContinuationToken(digest);
      return {
        type: 'CREATE_CONTINUATION_TOKEN_RESPONSE',
        token,
        expiresAt: new Date(Date.now() + 60 * 1000).toISOString(),
      };
    }

    case 'VALIDATE_CONTINUATION_TOKEN_REQUEST': {
      const digest = computeSha256(message.targetUrl);
      const isValid = await PolicyStore.validateAndConsumeContinuationToken(
        message.token,
        digest
      );
      return {
        type: 'VALIDATE_CONTINUATION_TOKEN_RESPONSE',
        isValid,
      };
    }

    case 'RESET_FACTORY_POLICY_REQUEST': {
      const factoryState = await PolicyStore.resetToFactory();
      if (threatEngine) {
        threatEngine.updatePolicy(factoryState.active_policy);
      }
      await DNRRuleManager.installPolicyRules(factoryState.active_policy);
      return {
        type: 'RESET_FACTORY_POLICY_RESPONSE',
        success: true,
        message: 'Reverted to factory policy 2026.10.1 (Seq 1).',
      };
    }

    default:
      return { error: `Unsupported message type: ${(message as unknown as { type: string }).type}` };
  }
}

