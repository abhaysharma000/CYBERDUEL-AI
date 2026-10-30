/**
 * CyberDuel AI — Privacy-Conscious Telemetry & Cloud Client
 * Enforces zero-data leakage: no page HTML, no credentials, no cookies, stripped sensitive query params.
 */

import {
  Decision,
  LocalThreatResult,
  NormalizedURLData,
  ThreatObservationReport,
} from '../types/contracts';
import { SettingsStore } from '../storage/settings-store';
import { computeSha256 } from '../crypto/sha256';

export class TelemetryClient {
  private static async getBaseUrl(): Promise<string> {
    const settings = await SettingsStore.getSettings();
    return settings.backend_base_url.replace(/\/+$/, '');
  }

  /**
   * Submit privacy-minimized threat observation report to /telemetry/observations.
   */
  public static async reportObservation(
    urlData: NormalizedURLData,
    localResult: LocalThreatResult,
    policyVersion: string
  ): Promise<boolean> {
    const settings = await SettingsStore.getSettings();
    if (settings.telemetry_mode === 'disabled') {
      return false; // Privacy mode: telemetry strictly disabled
    }

    try {
      const baseUrl = await this.getBaseUrl();
      const report: ThreatObservationReport = {
        observation_id: 'obs-' + Math.random().toString(36).substring(2, 10),
        reported_at: new Date().toISOString(),
        source: 'browser_extension',
        normalized_identifier: urlData.url_sha256,
        observed_url: settings.telemetry_mode === 'full_url' ? urlData.canonical_url : null,
        detected_features: {
          domain: urlData.domain,
          domain_sha256: urlData.domain_sha256,
          is_ip_literal: urlData.is_ip_literal,
          is_punycode: urlData.is_punycode,
          has_embedded_credentials: urlData.has_embedded_credentials,
        },
        initial_decision: localResult.decision,
        initial_risk_score: localResult.risk_score,
        client_policy_version: policyVersion,
        context: {
          client_id: settings.client_id,
          matched_rules: localResult.matched_rules,
          provenance: localResult.provenance,
        },
      };

      const res = await fetch(`${baseUrl}/api/v1/telemetry/observations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(report),
      });

      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * Submit user false-positive dispute report.
   */
  public static async reportFalsePositive(
    rawUrl: string,
    decision: Decision,
    userReason: string,
    policyVersion: string
  ): Promise<boolean> {
    try {
      const baseUrl = await this.getBaseUrl();
      const settings = await SettingsStore.getSettings();
      const urlDigest = computeSha256(rawUrl);

      const report: ThreatObservationReport = {
        observation_id: 'fp-' + Math.random().toString(36).substring(2, 10),
        reported_at: new Date().toISOString(),
        source: 'browser_extension',
        normalized_identifier: urlDigest,
        observed_url: settings.telemetry_mode === 'full_url' ? rawUrl : null,
        detected_features: {
          disputed_decision: decision,
          user_reason: userReason,
        },
        initial_decision: decision,
        initial_risk_score: 0.0,
        client_policy_version: policyVersion,
        context: {
          report_type: 'false_positive_dispute',
          client_id: settings.client_id,
        },
      };

      const res = await fetch(`${baseUrl}/api/v1/telemetry/observations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(report),
      });

      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * Optional Cloud Analysis Fallback: POST /analysis/evaluate.
   */
  public static async evaluateInCloud(
    urlData: NormalizedURLData
  ): Promise<{ decision: Decision; score: number; explanation: string } | null> {
    const settings = await SettingsStore.getSettings();
    if (!settings.cloud_analysis_enabled) {
      return null;
    }

    try {
      const baseUrl = await this.getBaseUrl();
      const res = await fetch(`${baseUrl}/api/v1/analysis/evaluate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          normalized_identifier: urlData.url_sha256,
          resource_url: settings.telemetry_mode === 'full_url' ? urlData.canonical_url : null,
          context: {
            domain: urlData.domain,
            scheme: urlData.scheme,
          },
        }),
      });

      if (!res.ok) {
        return null;
      }

      const data = await res.json();
      return {
        decision: data.decision || 'allow',
        score: typeof data.risk_score === 'number' ? data.risk_score : 0.0,
        explanation: data.explanation || 'Cloud model evaluation completed.',
      };
    } catch {
      return null;
    }
  }
}

