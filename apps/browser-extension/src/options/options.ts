/**
 * CyberDuel AI — Options & Architecture Onboarding Controller
 * Full settings management, privacy preferences, policy inspection, and diagnostics.
 */

import {
  GetProtectionStatusRequest,
  GetProtectionStatusResponse,
  GetSettingsRequest,
  GetSettingsResponse,
  ResetFactoryPolicyRequest,
  ResetFactoryPolicyResponse,
  TriggerUpdateCheckRequest,
  TriggerUpdateCheckResponse,
  UpdateSettingsRequest,
} from '../types/messages';
import { FACTORY_TRUST_ANCHORS } from '../storage/factory-policy';
import { PolicyStore } from '../storage/policy-store';

document.addEventListener('DOMContentLoaded', () => {
  // Navigation tabs
  const navItems = document.querySelectorAll('.nav-item');
  const tabPanes = document.querySelectorAll('.tab-pane');

  navItems.forEach((btn) => {
    btn.addEventListener('click', () => {
      const tabId = btn.getAttribute('data-tab');
      navItems.forEach((n) => n.classList.remove('active'));
      tabPanes.forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(`tab-${tabId}`);
      if (targetPane) {
        targetPane.classList.add('active');
      }

      if (tabId === 'activity') {
        loadRecentActivity();
      } else if (tabId === 'policy') {
        loadPolicyDetails();
      }
    });
  });

  // General tab elements
  const optProtectionEnabled = document.getElementById('optProtectionEnabled') as HTMLInputElement;
  const optChannelSelect = document.getElementById('optChannelSelect') as HTMLSelectElement;
  const optBackendUrl = document.getElementById('optBackendUrl') as HTMLInputElement;
  const optIntervalSelect = document.getElementById('optIntervalSelect') as HTMLSelectElement;
  const saveGeneralBtn = document.getElementById('saveGeneralBtn')!;
  const generalSaveMsg = document.getElementById('generalSaveMsg')!;

  // Privacy tab elements
  const modeMinimal = document.getElementById('modeMinimal') as HTMLInputElement;
  const modeDisabled = document.getElementById('modeDisabled') as HTMLInputElement;
  const modeFull = document.getElementById('modeFull') as HTMLInputElement;
  const optCloudAnalysis = document.getElementById('optCloudAnalysis') as HTMLInputElement;
  const savePrivacyBtn = document.getElementById('savePrivacyBtn')!;
  const privacySaveMsg = document.getElementById('privacySaveMsg')!;

  // Policy tab elements
  const dispPolicyVer = document.getElementById('dispPolicyVer')!;
  const dispPolicySeq = document.getElementById('dispPolicySeq')!;
  const dispInstallStatus = document.getElementById('dispInstallStatus')!;
  const dispVerifiedAt = document.getElementById('dispVerifiedAt')!;
  const trustKeysList = document.getElementById('trustKeysList')!;
  const optCheckUpdateBtn = document.getElementById('optCheckUpdateBtn')!;
  const optResetFactoryBtn = document.getElementById('optResetFactoryBtn')!;
  const policyActionStatus = document.getElementById('policyActionStatus')!;

  // Activity tab
  const recentEvalsBody = document.getElementById('recentEvalsBody')!;

  // Load Initial Settings
  loadSettings();
  loadPolicyDetails();

  function loadSettings() {
    const req: GetSettingsRequest = {
      type: 'GET_SETTINGS_REQUEST',
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(req, (resp: GetSettingsResponse) => {
      if (chrome.runtime.lastError || !resp || !resp.settings) return;
      const s = resp.settings;

      optProtectionEnabled.checked = s.protection_enabled;
      optChannelSelect.value = s.channel || 'stable';
      optBackendUrl.value = s.backend_base_url || 'https://cyberduel-ai-pabz.onrender.com';
      optIntervalSelect.value = String(s.update_check_interval_minutes || 30);

      if (s.telemetry_mode === 'disabled') {
        modeDisabled.checked = true;
      } else if (s.telemetry_mode === 'full_url') {
        modeFull.checked = true;
      } else {
        modeMinimal.checked = true;
      }

      optCloudAnalysis.checked = s.cloud_analysis_enabled;
    });
  }

  // Save General Settings
  saveGeneralBtn.addEventListener('click', () => {
    const req: UpdateSettingsRequest = {
      type: 'UPDATE_SETTINGS_REQUEST',
      settings: {
        protection_enabled: optProtectionEnabled.checked,
        channel: optChannelSelect.value as 'development' | 'canary' | 'stable',
        backend_base_url: optBackendUrl.value.trim(),
        update_check_interval_minutes: parseInt(optIntervalSelect.value, 10),
      },
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(req, () => {
      generalSaveMsg.textContent = 'Settings saved successfully.';
      generalSaveMsg.style.color = '#10b981';
      setTimeout(() => {
        generalSaveMsg.textContent = '';
      }, 3000);
    });
  });

  // Test Backend Connection
  const testBackendBtn = document.getElementById('testBackendBtn');
  const testBackendMsg = document.getElementById('testBackendMsg');
  if (testBackendBtn && testBackendMsg) {
    testBackendBtn.addEventListener('click', async () => {
      const url = optBackendUrl.value.trim().replace(/\/$/, '');
      testBackendMsg.textContent = 'Probing...';
      testBackendMsg.style.color = '#8b949e';
      try {
        const resp = await fetch(`${url}/health/live`);
        if (resp.ok) {
          testBackendMsg.textContent = 'Connected (HTTP 200)';
          testBackendMsg.style.color = '#10b981';
        } else {
          testBackendMsg.textContent = `Server HTTP ${resp.status}`;
          testBackendMsg.style.color = '#ef4444';
        }
      } catch {
        testBackendMsg.textContent = 'Failed to connect';
        testBackendMsg.style.color = '#ef4444';
      }
      setTimeout(() => {
        testBackendMsg.textContent = '';
      }, 5000);
    });
  }

  // Save Privacy Preferences
  savePrivacyBtn.addEventListener('click', () => {
    let mode: 'disabled' | 'minimal' | 'full_url' = 'minimal';
    if (modeDisabled.checked) mode = 'disabled';
    if (modeFull.checked) mode = 'full_url';

    const req: UpdateSettingsRequest = {
      type: 'UPDATE_SETTINGS_REQUEST',
      settings: {
        telemetry_mode: mode,
        cloud_analysis_enabled: optCloudAnalysis.checked,
      },
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(req, () => {
      privacySaveMsg.textContent = 'Privacy preferences saved.';
      privacySaveMsg.style.color = '#10b981';
      setTimeout(() => {
        privacySaveMsg.textContent = '';
      }, 3000);
    });
  });

  // Load Policy and Trust Keys
  function loadPolicyDetails() {
    const req: GetProtectionStatusRequest = {
      type: 'GET_PROTECTION_STATUS_REQUEST',
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(req, (resp: GetProtectionStatusResponse) => {
      if (chrome.runtime.lastError || !resp || !resp.status) return;
      const st = resp.status;
      dispPolicyVer.textContent = st.policyVersion;
      dispPolicySeq.textContent = `Seq ${st.sequenceNumber}`;
      dispInstallStatus.textContent = st.updateStatus.toUpperCase();
      dispVerifiedAt.textContent = st.lastUpdatedInstalledAt
        ? new Date(st.lastUpdatedInstalledAt).toLocaleString()
        : 'Initial Boot';
    });

    // Populate Trust Anchors
    trustKeysList.innerHTML = '';
    for (const key of FACTORY_TRUST_ANCHORS.active_keys) {
      const item = document.createElement('div');
      item.className = 'trust-key-item';
      item.innerHTML = `
        <div>
          <strong>${key.key_id}</strong> (${key.algorithm.toUpperCase()})
          <div style="font-size: 10px; color: #9ca3af; margin-top: 2px;">Status: ${key.status.toUpperCase()}</div>
        </div>
        <div style="color: #10b981; font-weight: 600;">TRUSTED ANCHOR</div>
      `;
      trustKeysList.appendChild(item);
    }
  }

  // Trigger Update Check
  optCheckUpdateBtn.addEventListener('click', () => {
    optCheckUpdateBtn.setAttribute('disabled', 'true');
    policyActionStatus.textContent = 'Querying release authority...';
    policyActionStatus.style.color = '#9ca3af';

    const req: TriggerUpdateCheckRequest = {
      type: 'TRIGGER_UPDATE_CHECK_REQUEST',
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(req, (resp: TriggerUpdateCheckResponse) => {
      optCheckUpdateBtn.removeAttribute('disabled');
      if (resp && resp.success) {
        policyActionStatus.textContent = resp.message;
        policyActionStatus.style.color = '#10b981';
        loadPolicyDetails();
      } else {
        policyActionStatus.textContent = resp ? resp.message : 'Update check failed.';
        policyActionStatus.style.color = '#ef4444';
      }
    });
  });

  // Reset to Factory Default
  optResetFactoryBtn.addEventListener('click', () => {
    const ok = window.confirm(
      'Are you sure you want to revert to the factory default policy (2026.10.1)?'
    );
    if (!ok) return;

    const req: ResetFactoryPolicyRequest = {
      type: 'RESET_FACTORY_POLICY_REQUEST',
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(req, (resp: ResetFactoryPolicyResponse) => {
      if (resp && resp.success) {
        policyActionStatus.textContent = resp.message;
        policyActionStatus.style.color = '#10b981';
        loadPolicyDetails();
      }
    });
  });

  // Load Recent Activity Table
  async function loadRecentActivity() {
    const evals = await PolicyStore.getRecentEvaluations();
    recentEvalsBody.innerHTML = '';

    if (evals.length === 0) {
      recentEvalsBody.innerHTML = '<tr><td colspan="5" class="empty-cell">No evaluations recorded yet.</td></tr>';
      return;
    }

    for (const item of evals) {
      const row = document.createElement('tr');
      const timeStr = new Date(item.evaluated_at).toLocaleTimeString();
      row.innerHTML = `
        <td><span class="table-badge badge-${item.decision}">${item.decision.toUpperCase()}</span></td>
        <td><strong>${item.risk_score.toFixed(2)}</strong></td>
        <td style="font-family: monospace; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(item.canonical_url)}</td>
        <td style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(item.explanation)}</td>
        <td style="color: #9ca3af;">${timeStr}</td>
      `;
      recentEvalsBody.appendChild(row);
    }
  }

  function escapeHtml(str: string): string {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
});

