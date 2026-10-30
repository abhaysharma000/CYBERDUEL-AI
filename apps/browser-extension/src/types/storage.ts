/**
 * CyberDuel AI — Local Storage Contracts for Edge Extension
 */

import { PolicyBundle, ReleaseManifest } from './contracts';

export interface ExtensionSettings {
  protection_enabled: boolean;
  telemetry_mode: 'disabled' | 'minimal' | 'full_url';
  cloud_analysis_enabled: boolean;
  backend_base_url: string;
  update_check_interval_minutes: number;
  client_id: string;
  channel: 'development' | 'canary' | 'stable';
}

export interface StoredPolicyState {
  active_policy: PolicyBundle;
  active_manifest: ReleaseManifest | null;
  sequence_number: number;
  last_verified_at: string;
  installation_status: 'installed' | 'failed' | 'rolled_back';
  previous_policy?: PolicyBundle | null;
  previous_manifest?: ReleaseManifest | null;
  last_update_check_at?: string | null;
  last_update_status?: 'idle' | 'checking' | 'downloading' | 'verified' | 'installed' | 'error';
  last_error_message?: string | null;
}

export interface RecentEvaluation {
  url: string;
  canonical_url: string;
  decision: 'allow' | 'warn' | 'block';
  risk_score: number;
  explanation: string;
  evaluated_at: string;
}

export interface BoundedContinuationToken {
  token: string;
  target_url_sha256: string;
  created_at: number;
  expires_at: number;
}

