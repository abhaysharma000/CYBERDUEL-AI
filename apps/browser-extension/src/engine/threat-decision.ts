/**
 * CyberDuel AI — Local Threat Decision Engine
 * Orchestrates URL normalization, indicator lookup, declarative rules, and heuristic scoring.
 */

import {
  Decision,
  EvidenceItem,
  LocalThreatResult,
  NormalizedURLData,
  PolicyBundle,
  ProvenanceType,
} from '../types/contracts';
import { URLNormalizer, URLNormalizationError } from './normalizer';
import { ExtractedFeatures, URLFeatureExtractor } from './feature-extractor';
import { HeuristicAnalyzer } from './heuristics';
import { DeclarativeRuleEvaluator } from './rule-evaluator';

export class LocalThreatEngine {
  private activePolicy: PolicyBundle;

  constructor(policy: PolicyBundle) {
    this.activePolicy = policy;
  }

  public updatePolicy(newPolicy: PolicyBundle): void {
    this.activePolicy = newPolicy;
  }

  public getPolicyVersion(): string {
    return this.activePolicy.policy_version;
  }

  public evaluate(rawUrl: string): LocalThreatResult {
    const evaluatedAt = new Date().toISOString();
    const isStale = new Date(this.activePolicy.expires_at).getTime() < Date.now();

    // 1. Safe normalization
    let normalized: NormalizedURLData;
    try {
      normalized = URLNormalizer.normalize(rawUrl);
    } catch (err) {
      const msg = err instanceof URLNormalizationError ? err.message : String(err);
      return {
        decision: 'allow', // Invalid or unsupported schemes (e.g. internal pages, chrome://) are not blocked
        risk_score: 0.0,
        confidence: 0.1,
        evidence: [
          {
            rule_id: 'NORM-UNSUPPORTED-OR-INVALID',
            description: `URL could not be parsed: ${msg}`,
            severity: 'low',
            score_contribution: 0.0,
            confidence: 0.1,
          },
        ],
        explanation: `Destination URL could not be normalized: ${msg}`,
        policy_version: this.activePolicy.policy_version,
        matched_rules: [],
        provenance: 'heuristic',
        is_stale: isStale,
        evaluated_at: evaluatedAt,
      };
    }

    // 2. Exact Threat Indicator Lookup (High-Confidence Threat Intelligence)
    if (this.activePolicy.threat_indicators && this.activePolicy.threat_indicators.length > 0) {
      for (const indicator of this.activePolicy.threat_indicators) {
        let matched = false;
        if (indicator.type === 'url_hash' && indicator.hash_sha256 === normalized.url_sha256) {
          matched = true;
        } else if (indicator.type === 'domain_hash' && indicator.hash_sha256 === normalized.domain_sha256) {
          matched = true;
        } else if (indicator.type === 'domain' && indicator.value.toLowerCase() === normalized.domain) {
          matched = true;
        }

        if (matched) {
          const evidence: EvidenceItem = {
            rule_id: `IND-${indicator.indicator_id}`,
            description: indicator.description || `Confirmed threat indicator match for ${indicator.value}`,
            severity: indicator.severity,
            score_contribution: 1.0,
            confidence: 0.99,
            metadata: {
              indicator_type: indicator.type,
              indicator_value: indicator.value,
            },
          };

          return {
            decision: indicator.action,
            risk_score: 1.0,
            confidence: 0.99,
            evidence: [evidence],
            explanation: `Confirmed malicious destination matching threat intelligence record '${indicator.indicator_id}'.`,
            policy_version: this.activePolicy.policy_version,
            matched_rules: [indicator.indicator_id],
            provenance: 'threat_intelligence',
            is_stale: isStale,
            evaluated_at: evaluatedAt,
          };
        }
      }
    }

    // 3. Extract Features
    const features: ExtractedFeatures = URLFeatureExtractor.extract(normalized);

    // 4. Declarative Rules Evaluation
    const allEvidence: EvidenceItem[] = [];
    const matchedRules: string[] = [];
    let ruleMaxAction: Decision = 'allow';
    let ruleScoreSum = 0.0;

    if (this.activePolicy.rules && this.activePolicy.rules.length > 0) {
      for (const rule of this.activePolicy.rules) {
        const outcome = DeclarativeRuleEvaluator.evaluateRule(rule, features);
        if (outcome && outcome.matched) {
          matchedRules.push(outcome.rule_id);
          allEvidence.push(outcome.evidence);
          ruleScoreSum += outcome.weight;

          if (outcome.action === 'block') {
            ruleMaxAction = 'block';
          } else if (outcome.action === 'warn' && ruleMaxAction !== 'block') {
            ruleMaxAction = 'warn';
          }
        }
      }
    }

    // If an explicit declarative rule fired with action 'block', enforce it
    if (ruleMaxAction === 'block') {
      return {
        decision: 'block',
        risk_score: Math.min(1.0, Math.max(0.85, ruleScoreSum)),
        confidence: 0.92,
        evidence: allEvidence,
        explanation: `Blocked by active declarative defense policy rule(s): ${matchedRules.join(', ')}.`,
        policy_version: this.activePolicy.policy_version,
        matched_rules: matchedRules,
        provenance: 'rule_engine',
        is_stale: isStale,
        evaluated_at: evaluatedAt,
      };
    }

    // 5. Heuristic Analysis
    const heuristicOutcome = HeuristicAnalyzer.analyze(features);
    allEvidence.push(...heuristicOutcome.evidence);

    // 6. Aggregate Scoring
    const totalScore = Math.min(1.0, Math.max(heuristicOutcome.heuristicScore, ruleScoreSum));
    const warnThresh = this.activePolicy.scoring_thresholds?.warn_threshold ?? 0.50;
    const blockThresh = this.activePolicy.scoring_thresholds?.block_threshold ?? 0.85;

    let decision: Decision = 'allow';
    let explanation = 'Destination exhibits standard benign characteristics.';
    let provenance: ProvenanceType = 'heuristic';

    if (ruleMaxAction === 'warn' || totalScore >= blockThresh) {
      if (totalScore >= blockThresh) {
        decision = 'block';
        explanation = `Destination exceeds malicious risk threshold (${totalScore.toFixed(2)} >= ${blockThresh.toFixed(2)}).`;
      } else {
        decision = 'warn';
        explanation = `Destination exhibits suspicious indicators requiring caution (${totalScore.toFixed(2)} >= ${warnThresh.toFixed(2)}).`;
      }
      provenance = matchedRules.length > 0 ? 'rule_engine' : 'heuristic';
    } else if (totalScore >= warnThresh) {
      decision = 'warn';
      explanation = `Destination exhibits suspicious indicators requiring caution (${totalScore.toFixed(2)} >= ${warnThresh.toFixed(2)}).`;
      provenance = 'heuristic';
    }

    const confidence = allEvidence.length > 0 ? 0.85 : 0.60;

    return {
      decision,
      risk_score: Math.round(totalScore * 1000) / 1000,
      confidence,
      evidence: allEvidence,
      explanation,
      policy_version: this.activePolicy.policy_version,
      matched_rules: matchedRules,
      provenance,
      is_stale: isStale,
      evaluated_at: evaluatedAt,
    };
  }
}
