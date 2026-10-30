/**
 * CyberDuel AI — Factory Default Bootstrap Policy and Trust Anchors
 * Bundled offline fallback policy when no network update has yet been verified.
 */

import { PolicyBundle, TrustAnchorSet } from '../types/contracts';

export const FACTORY_POLICY_BUNDLE: PolicyBundle = {
  bundle_id: '00000000-0000-0000-0000-000000000001',
  policy_version: '2026.10.1',
  sequence_number: 1,
  scoring_thresholds: {
    warn_threshold: 0.50,
    block_threshold: 0.85,
  },
  rules: [
    {
      rule_id: 'RULE-EMBEDDED-CREDENTIALS',
      rule_version: '1.0.0',
      name: 'Disguised Authority Credential Injection',
      description: 'Blocks URLs containing embedded username or password authentication syntax.',
      severity: 'critical',
      action: 'block',
      predicates: [
        {
          field: 'has_embedded_credentials',
          operator: 'eq',
          value: true,
        },
      ],
      weight: 0.95,
    },
    {
      rule_id: 'RULE-UNVERIFIED-BRAND-MIMICRY',
      rule_version: '1.0.0',
      name: 'Unverified High-Value Brand Mimicry',
      description: 'Warns on destinations containing target brand names hosted on non-official domains.',
      severity: 'high',
      action: 'warn',
      predicates: [
        {
          field: 'brand_token_detected',
          operator: 'eq',
          value: true,
        },
      ],
      weight: 0.65,
    },
    {
      rule_id: 'RULE-RAW-IP-HOST-WITH-KEYWORDS',
      rule_version: '1.0.0',
      name: 'Raw IP Host with Phishing Tokens',
      description: 'Warns when an IP address literal is used alongside credential harvesting keywords.',
      severity: 'high',
      action: 'warn',
      predicates: [
        {
          field: 'is_ip_literal',
          operator: 'eq',
          value: true,
        },
        {
          field: 'phish_keyword_count',
          operator: 'gt',
          value: 0,
        },
      ],
      weight: 0.75,
    },
  ],
  threat_indicators: [
    {
      indicator_id: 'IND-MALICIOUS-TEST-DOMAIN',
      type: 'domain',
      value: 'malicious-phish-portal.test',
      hash_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      severity: 'critical',
      action: 'block',
      description: 'Known confirmed phishing testing portal.',
    },
  ],
  feature_weights: {
    brand_token_detected: 0.65,
    has_embedded_credentials: 0.70,
    is_ip_literal: 0.50,
    is_punycode: 0.55,
  },
  schema_version: '1.0.0',
  created_at: '2026-10-01T00:00:00Z',
  expires_at: '2027-12-31T23:59:59Z',
  metadata: {
    origin: 'factory_bootstrap',
    build: '2026.10-release',
  },
};

export const FACTORY_TRUST_ANCHORS: TrustAnchorSet = {
  active_keys: [
    {
      key_id: 'cyberduel-prod-2026-k1',
      algorithm: 'ed25519',
      public_key_pem:
        '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAObvvQ00bruMF1ZvF33Cfr5GnaEstiK8R1dJqpX8dSBI=\n-----END PUBLIC KEY-----\n',
      status: 'active',
      valid_from: '2026-10-01T00:00:00Z',
      valid_until: '2028-10-01T00:00:00Z',
    },
  ],
  revoked_keys: [],
  timestamp: '2026-10-01T00:00:00Z',
};

