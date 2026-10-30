/**
 * CyberDuel AI — Canonical Type Contracts for Browser Extension Edge Client
 * Mirrored from packages/shared-contracts (Pydantic models) to ensure 100% schema alignment.
 */

export type Decision = 'allow' | 'warn' | 'block';
export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ProvenanceType = 'heuristic' | 'threat_intelligence' | 'rule_engine' | 'cloud_model';
export type ReleaseChannel = 'development' | 'canary' | 'stable' | 'emergency';
export type ReleaseStatus = 'draft' | 'staged' | 'published' | 'deprecated' | 'revoked' | 'rolled_back';
export type KeyStatus = 'active' | 'rotated' | 'revoked';

export interface EvidenceItem {
  rule_id: string;
  description: string;
  severity: ThreatSeverity;
  score_contribution: number;
  confidence: number;
  metadata?: Record<string, unknown>;
}

export interface LocalThreatResult {
  decision: Decision;
  risk_score: number;
  confidence: number;
  evidence: EvidenceItem[];
  explanation: string;
  policy_version: string;
  matched_rules: string[];
  provenance: ProvenanceType;
  is_stale: boolean;
  evaluated_at: string;
}

export interface NormalizedURLData {
  raw_input: string;
  scheme: string;
  host: string;
  unicode_host: string;
  port: number | null;
  path: string;
  query: string | null;
  fragment: string | null;
  canonical_url: string;
  domain: string;
  subdomains: string[];
  url_sha256: string;
  domain_sha256: string;
  has_embedded_credentials: boolean;
  userinfo: string | null;
  is_ip_literal: boolean;
  is_punycode: boolean;
}

export interface RulePredicate {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'contains' | 'in' | 'matches_regex';
  value: string | number | boolean | Array<string | number>;
}

export interface DeclarativeRule {
  rule_id: string;
  rule_version: string;
  name: string;
  description: string;
  severity: ThreatSeverity;
  action: Decision;
  predicates: RulePredicate[];
  weight: number;
}

export interface ThreatIndicator {
  indicator_id: string;
  type: string; // 'url_hash' | 'domain_hash' | 'domain' | 'prefix'
  value: string;
  hash_sha256: string;
  severity: ThreatSeverity;
  action: Decision;
  description: string;
}

export interface ScoringThresholds {
  warn_threshold: number;
  block_threshold: number;
}

export interface PolicyBundle {
  bundle_id: string;
  policy_version: string;
  sequence_number: number;
  scoring_thresholds: ScoringThresholds;
  rules: DeclarativeRule[];
  threat_indicators: ThreatIndicator[];
  feature_weights: Record<string, number>;
  schema_version: string;
  created_at: string;
  expires_at: string;
  metadata: Record<string, unknown>;
}

export interface ReleaseManifest {
  release_id: string;
  policy_version: string;
  sequence_number: number;
  channel: ReleaseChannel;
  status: ReleaseStatus;
  published_at: string;
  expires_at: string;
  min_client_version: string;
  max_client_version?: string | null;
  min_engine_version: string;
  supported_platforms: string[];
  artifact_digest: string;
  artifact_size_bytes: number;
  artifact_url: string;
  publisher_key_id: string;
  signature: string;
  is_mandatory: boolean;
  is_rollback: boolean;
  rollback_target_version?: string | null;
  release_notes: string;
  metadata: Record<string, unknown>;
}

export interface SigningKeyMetadata {
  key_id: string;
  algorithm: string;
  public_key_pem: string;
  status: KeyStatus;
  valid_from: string;
  valid_until?: string | null;
  revoked_at?: string | null;
  revocation_reason?: string | null;
}

export interface TrustAnchorSet {
  active_keys: SigningKeyMetadata[];
  revoked_keys: SigningKeyMetadata[];
  timestamp: string;
}

export interface UpdateCheckRequest {
  client_id: string;
  client_version: string;
  engine_version: string;
  current_policy_version: string;
  current_sequence_number: number;
  channel: ReleaseChannel;
  platform: string;
}

export interface UpdateCheckResponse {
  update_available: boolean;
  latest_version?: string | null;
  latest_sequence_number?: number | null;
  manifest_url?: string | null;
  is_mandatory: boolean;
  is_rollback: boolean;
  rollback_target_version?: string | null;
  checked_at: string;
  release_notes?: string | null;
}

export interface UpdateAcknowledgement {
  acknowledgement_id: string;
  client_id: string;
  release_id: string;
  policy_version: string;
  sequence_number: number;
  status: 'installed' | 'failed' | 'rolled_back';
  error_message?: string | null;
  is_rollback_applied: boolean;
  channel: ReleaseChannel;
  reported_at: string;
}

export interface ThreatObservationReport {
  observation_id: string;
  reported_at: string;
  source: 'browser_extension' | 'mobile_agent' | 'laboratory';
  normalized_identifier: string; // SHA-256 target digest
  observed_url?: string | null;
  detected_features: Record<string, unknown>;
  initial_decision: Decision;
  initial_risk_score: number;
  client_policy_version: string;
  context: Record<string, unknown>;
}

