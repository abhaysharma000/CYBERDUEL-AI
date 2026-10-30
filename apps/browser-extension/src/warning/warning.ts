/**
 * CyberDuel AI — Warning Interstitial Controller
 * Safely renders threat details and provides safe-return or bounded single-use continuation flows.
 */

import { Decision } from '../types/contracts';
import {
  CreateContinuationTokenRequest,
  CreateContinuationTokenResponse,
  SubmitFalsePositiveRequest,
  SubmitFalsePositiveResponse,
  ValidateContinuationTokenRequest,
  ValidateContinuationTokenResponse,
} from '../types/messages';

document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get('url') || 'Unknown destination';
  const decision = (params.get('decision') as Decision) || 'warn';
  const score = params.get('score') || '0.00';
  const reason = params.get('reason') || 'Destination triggered defensive security policy.';
  const policy = params.get('policy') || 'Unknown';

  const alertCard = document.getElementById('alertCard')!;
  const shieldIcon = document.getElementById('shieldIcon')!;
  const alertBadge = document.getElementById('alertBadge')!;
  const alertTitle = document.getElementById('alertTitle')!;
  const alertReason = document.getElementById('alertReason')!;
  const targetUrlText = document.getElementById('targetUrlText')!;
  const decisionText = document.getElementById('decisionText')!;
  const riskScoreText = document.getElementById('riskScoreText')!;
  const policyVersionText = document.getElementById('policyVersionText')!;
  const goBackBtn = document.getElementById('goBackBtn')!;
  const proceedBtn = document.getElementById('proceedBtn')!;
  const reportFpBtn = document.getElementById('reportFpBtn')!;
  const feedbackPanel = document.getElementById('feedbackPanel')!;
  const fpReasonText = document.getElementById('fpReasonText') as HTMLTextAreaElement;
  const submitFpBtn = document.getElementById('submitFpBtn')!;
  const cancelFpBtn = document.getElementById('cancelFpBtn')!;
  const fpStatusText = document.getElementById('fpStatusText')!;

  // Safe text rendering: use textContent exclusively to avoid XSS
  targetUrlText.textContent = targetUrl;
  decisionText.textContent = decision.toUpperCase();
  riskScoreText.textContent = parseFloat(score).toFixed(2);
  alertReason.textContent = reason;
  policyVersionText.textContent = policy;

  if (decision === 'block') {
    alertCard.className = 'alert-card mode-block';
    shieldIcon.textContent = '🛑';
    alertBadge.className = 'badge badge-danger';
    alertBadge.textContent = 'BLOCKED: CONFIRMED THREAT';
    alertTitle.textContent = 'Navigation Terminated by Defense Policy';
    // Strictly hide the proceed button for confirmed blocks
    proceedBtn.style.display = 'none';
  } else {
    alertCard.className = 'alert-card mode-warn';
    shieldIcon.textContent = '⚠️';
    alertBadge.className = 'badge badge-warning';
    alertBadge.textContent = 'WARNING: SUSPICIOUS DESTINATION';
    alertTitle.textContent = 'Heuristic Security Warning';
    // Show one-time proceed button with strict confirmation
    proceedBtn.style.display = 'block';
  }

  // Safe Return handler
  goBackBtn.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  // Bounded One-Time Proceed handler (Warnings only)
  proceedBtn.addEventListener('click', () => {
    const confirmed = window.confirm(
      'CAUTION: Proceeding to this destination may expose your credentials or device to harm.\n\nAre you certain you wish to override this heuristic warning?'
    );
    if (!confirmed) return;

    // Request single-use bounded continuation token
    const tokenReq: CreateContinuationTokenRequest = {
      type: 'CREATE_CONTINUATION_TOKEN_REQUEST',
      targetUrl,
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(tokenReq, (resp: CreateContinuationTokenResponse) => {
      if (chrome.runtime.lastError || !resp || !resp.token) {
        alert('Could not validate continuation credentials with background security authority.');
        return;
      }

      // Validate token before navigation
      const validateReq: ValidateContinuationTokenRequest = {
        type: 'VALIDATE_CONTINUATION_TOKEN_REQUEST',
        token: resp.token,
        targetUrl,
        timestamp: new Date().toISOString(),
      };

      chrome.runtime.sendMessage(validateReq, (valResp: ValidateContinuationTokenResponse) => {
        if (valResp && valResp.isValid) {
          window.location.replace(targetUrl);
        } else {
          alert('Continuation token expired or invalid.');
        }
      });
    });
  });

  // False positive report toggle
  reportFpBtn.addEventListener('click', () => {
    feedbackPanel.style.display = feedbackPanel.style.display === 'none' ? 'block' : 'none';
  });

  cancelFpBtn.addEventListener('click', () => {
    feedbackPanel.style.display = 'none';
  });

  submitFpBtn.addEventListener('click', () => {
    const userReason = fpReasonText.value.trim();
    if (!userReason) {
      fpStatusText.textContent = 'Please provide a brief reason for the report.';
      fpStatusText.style.color = '#fca5a5';
      return;
    }

    submitFpBtn.setAttribute('disabled', 'true');
    fpStatusText.textContent = 'Transmitting observation to lab...';
    fpStatusText.style.color = '#9ca3af';

    const fpReq: SubmitFalsePositiveRequest = {
      type: 'SUBMIT_FALSE_POSITIVE_REQUEST',
      targetUrl,
      reportedDecision: decision,
      reason: userReason,
      timestamp: new Date().toISOString(),
    };

    chrome.runtime.sendMessage(fpReq, (resp: SubmitFalsePositiveResponse) => {
      if (resp && resp.success) {
        fpStatusText.textContent = 'Dispute recorded for laboratory triage. Thank you.';
        fpStatusText.style.color = '#10b981';
        setTimeout(() => {
          feedbackPanel.style.display = 'none';
        }, 2000);
      } else {
        fpStatusText.textContent = 'Failed to submit report. Staged locally.';
        fpStatusText.style.color = '#fca5a5';
        submitFpBtn.removeAttribute('disabled');
      }
    });
  });
});
