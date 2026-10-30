/**
 * CyberDuel AI — Popup Action Controller
 * Real-time protection status monitoring, URL threat inspection, and manual update triggers.
 */

import {
  EvaluateURLRequest,
  EvaluateURLResponse,
  GetProtectionStatusRequest,
  GetProtectionStatusResponse,
  ProtectionStatusData,
  TriggerUpdateCheckRequest,
  TriggerUpdateCheckResponse,
  UpdateSettingsRequest,
} from '../types/messages';

document.addEventListener('DOMContentLoaded', () => {
  const statusDot = document.getElementById('statusDot')!;
  const statusLabel = document.getElementById('statusLabel')!;
  const protectionToggle = document.getElementById('protectionToggle') as HTMLInputElement;
  const switchSubtitle = document.getElementById('switchSubtitle')!;
  const policyVerVal = document.getElementById('policyVerVal')!;
  const policySeqVal = document.getElementById('policySeqVal')!;
  const dnrRulesVal = document.getElementById('dnrRulesVal')!;
  const cloudSyncVal = document.getElementById('cloudSyncVal')!;
  const urlInput = document.getElementById('urlInput') as HTMLInputElement;
  const inspectCurrentTabBtn = document.getElementById('inspectCurrentTabBtn')!;
  const evaluateBtn = document.getElementById('evaluateBtn')!;
  const evalResultContainer = document.getElementById('evalResultContainer')!;
  const evalDecisionBadge = document.getElementById('evalDecisionBadge')!;
  const evalScore = document.getElementById('evalScore')!;
  const evalExplanation = document.getElementById('evalExplanation')!;
  const evalProvenance = document.getElementById('evalProvenance')!;
  const checkUpdateBtn = document.getElementById('checkUpdateBtn')!;
  const updateBtnText = document.getElementById('updateBtnText')!;
  const updateStatusMsg = document.getElementById('updateStatusMsg')!;
  const openOptionsBtn = document.getElementById('openOptionsBtn')!;
  const lastCheckMeta = document.getElementById('lastCheckMeta')!;

  // 1. Fetch initial status
  refreshProtectionStatus();

  function refreshProtectionStatus() {
    const req: GetProtectionStatusRequest = {
      type: 'GET_PROTECTION_STATUS_REQUEST',
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(req, (resp: GetProtectionStatusResponse) => {
      if (chrome.runtime.lastError || !resp || !resp.status) {
        statusLabel.textContent = 'OFFLINE';
        statusDot.style.backgroundColor = '#8b949e';
        return;
      }
      applyStatusData(resp.status);
    });
  }

  function applyStatusData(status: ProtectionStatusData) {
    protectionToggle.checked = status.isEnabled;

    if (!status.isEnabled) {
      statusLabel.textContent = 'DISABLED';
      statusDot.style.backgroundColor = '#da3633';
      switchSubtitle.textContent = 'Protection paused by user';
    } else if (status.isStale) {
      statusLabel.textContent = 'POLICY STALE';
      statusDot.style.backgroundColor = '#d29922';
      switchSubtitle.textContent = 'Policy expired — refresh required';
    } else {
      statusLabel.textContent = 'PROTECTED';
      statusDot.style.backgroundColor = '#3fb950';
      switchSubtitle.textContent = 'Synchronous DNR & Link Guard active';
    }

    policyVerVal.textContent = status.policyVersion || '—';
    policySeqVal.textContent = status.sequenceNumber ? `Seq ${status.sequenceNumber}` : '—';
    dnrRulesVal.textContent = `${status.activeDNRRuleCount}`;
    cloudSyncVal.textContent = status.cloudConnected ? 'Live' : 'Cached';

    if (status.lastUpdateCheckedAt) {
      const dt = new Date(status.lastUpdateCheckedAt);
      lastCheckMeta.textContent = `Checked: ${dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
    } else {
      lastCheckMeta.textContent = 'Checked: Initial';
    }
  }

  // 2. Protection Toggle Handler
  protectionToggle.addEventListener('change', () => {
    const enabled = protectionToggle.checked;
    const req: UpdateSettingsRequest = {
      type: 'UPDATE_SETTINGS_REQUEST',
      settings: { protection_enabled: enabled },
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(req, () => {
      refreshProtectionStatus();
    });
  });

  // 3. Inspect Current Tab
  inspectCurrentTabBtn.addEventListener('click', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs.length > 0 && tabs[0].url) {
        urlInput.value = tabs[0].url;
        performEvaluation(tabs[0].url);
      }
    });
  });

  // 4. Manual URL Evaluation
  evaluateBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    if (!url) return;
    performEvaluation(url);
  });

  function performEvaluation(targetUrl: string) {
    evaluateBtn.setAttribute('disabled', 'true');
    evalResultContainer.style.display = 'block';
    evalExplanation.textContent = 'Analyzing destination structure, heuristics, and rules...';
    evalDecisionBadge.className = 'eval-decision-badge';
    evalDecisionBadge.textContent = '...';

    const req: EvaluateURLRequest = {
      type: 'EVALUATE_URL_REQUEST',
      url: targetUrl,
      source: 'popup_manual',
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(req, (resp: EvaluateURLResponse) => {
      evaluateBtn.removeAttribute('disabled');
      if (chrome.runtime.lastError || !resp || !resp.result) {
        evalResultContainer.className = 'eval-result';
        evalDecisionBadge.textContent = 'ERROR';
        evalExplanation.textContent = 'Failed to communicate with local decision engine.';
        return;
      }

      const res = resp.result;
      evalDecisionBadge.textContent = res.decision.toUpperCase();
      evalDecisionBadge.className = `eval-decision-badge badge-${res.decision}`;
      evalResultContainer.className = `eval-result mode-${res.decision}`;
      evalScore.textContent = `Risk: ${res.risk_score.toFixed(2)}`;
      evalExplanation.textContent = res.explanation;
      evalProvenance.textContent = `Provenance: ${res.provenance.replace('_', ' ').toUpperCase()} • Policy ${res.policy_version}`;
    });
  }

  // 5. Update Check Trigger
  checkUpdateBtn.addEventListener('click', () => {
    checkUpdateBtn.setAttribute('disabled', 'true');
    updateBtnText.textContent = 'Checking update...';
    updateStatusMsg.textContent = 'Connecting to CyberDuel release authority...';
    updateStatusMsg.style.color = '#8b949e';

    const req: TriggerUpdateCheckRequest = {
      type: 'TRIGGER_UPDATE_CHECK_REQUEST',
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(req, (resp: TriggerUpdateCheckResponse) => {
      checkUpdateBtn.removeAttribute('disabled');
      updateBtnText.textContent = 'Check for Policy Updates';

      if (chrome.runtime.lastError || !resp) {
        updateStatusMsg.textContent = 'Cloud authority unreachable.';
        updateStatusMsg.style.color = '#da3633';
        return;
      }

      if (resp.success) {
        updateStatusMsg.textContent = resp.message;
        updateStatusMsg.style.color = '#3fb950';
        refreshProtectionStatus();
      } else {
        updateStatusMsg.textContent = resp.message;
        updateStatusMsg.style.color = '#da3633';
      }
    });
  });

  // 6. Open Options Page
  openOptionsBtn.addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('options.html'));
    }
  });
});

