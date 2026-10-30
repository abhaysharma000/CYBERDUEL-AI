/**
 * CyberDuel AI — Heuristic Threat Analyzer
 * Transparent client-side heuristic rules detecting brand mimicry, punycode deception, and IP hosts.
 */

import { EvidenceItem } from '../types/contracts';
import { ExtractedFeatures } from './feature-extractor';

export const SUSPICIOUS_TLDS = new Set([
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'top',
  'buzz',
  'icu',
  'rest',
  'work',
]);

export interface HeuristicAnalysisOutcome {
  heuristicScore: number;
  evidence: EvidenceItem[];
}

export class HeuristicAnalyzer {
  public static analyze(features: ExtractedFeatures): HeuristicAnalysisOutcome {
    const evidence: EvidenceItem[] = [];
    let score = 0.0;

    // 1. Whitelist bypass
    if (features.is_whitelisted) {
      evidence.push({
        rule_id: 'HEUR-WHITELIST-TOP-DOMAIN',
        description: `Verified top-tier trusted domain (${features.domain}).`,
        severity: 'low',
        score_contribution: -0.8,
        confidence: 0.95,
      });
      return { heuristicScore: 0.0, evidence };
    }

    // 2. Brand token impersonation
    if (features.brand_token_detected) {
      score += 0.65;
      evidence.push({
        rule_id: 'HEUR-BRAND-IMPERSONATION',
        description: `Host '${features.host}' contains a high-value brand keyword on an unverified domain '${features.domain}'.`,
        severity: 'high',
        score_contribution: 0.65,
        confidence: 0.85,
      });
    }

    // 3. Embedded credentials in authority
    if (features.has_embedded_credentials) {
      score += 0.70;
      evidence.push({
        rule_id: 'HEUR-EMBEDDED-CREDENTIALS',
        description: 'URL authority contains embedded credentials, a common phishing tactic to disguise real host.',
        severity: 'critical',
        score_contribution: 0.70,
        confidence: 0.90,
      });
    }

    // 4. IP literal host
    if (features.is_ip_literal) {
      score += 0.50;
      evidence.push({
        rule_id: 'HEUR-IP-LITERAL-HOST',
        description: `Host is a raw IP literal (${features.host}) instead of a registered domain.`,
        severity: 'medium',
        score_contribution: 0.50,
        confidence: 0.80,
      });
    }

    // 5. Punycode / IDN deception
    if (features.is_punycode) {
      score += 0.55;
      evidence.push({
        rule_id: 'HEUR-PUNYCODE-HOMOGRAPH',
        description: `Host contains Punycode ('${features.host}'), indicating potential homograph deception.`,
        severity: 'high',
        score_contribution: 0.55,
        confidence: 0.75,
      });
    }

    // 6. Suspicious TLD
    const tld = features.domain.split('.').pop() || '';
    if (SUSPICIOUS_TLDS.has(tld)) {
      score += 0.35;
      evidence.push({
        rule_id: 'HEUR-SUSPICIOUS-TLD',
        description: `Domain uses top-level domain '.${tld}' with elevated historical abuse rates.`,
        severity: 'medium',
        score_contribution: 0.35,
        confidence: 0.60,
      });
    }

    // 7. High host entropy
    if (features.host_entropy > 4.2 && !features.is_ip_literal) {
      score += 0.30;
      evidence.push({
        rule_id: 'HEUR-HIGH-HOST-ENTROPY',
        description: `Host lexical entropy (${features.host_entropy}) indicates algorithmic or randomized generation.`,
        severity: 'medium',
        score_contribution: 0.30,
        confidence: 0.65,
      });
    }

    // 8. Phishing keywords combined with suspicious characteristics
    if (features.phish_keyword_count > 0 && (score > 0.3 || features.subdomain_count > 2)) {
      const kwBonus = Math.min(features.phish_keyword_count * 0.15, 0.40);
      score += kwBonus;
      evidence.push({
        rule_id: 'HEUR-PHISHING-KEYWORDS',
        description: `URL contains ${features.phish_keyword_count} credential harvesting keyword(s) in suspicious context.`,
        severity: 'medium',
        score_contribution: kwBonus,
        confidence: 0.70,
      });
    }

    // Bound score between 0.0 and 1.0
    const clampedScore = Math.max(0.0, Math.min(1.0, score));
    return {
      heuristicScore: Math.round(clampedScore * 1000) / 1000,
      evidence,
    };
  }
}

