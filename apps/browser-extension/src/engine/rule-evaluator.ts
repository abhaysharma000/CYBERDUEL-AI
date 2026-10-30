/**
 * CyberDuel AI — Declarative AST Rule Evaluator
 * Safely evaluates declarative predicate logic against extracted features without eval() or dynamic code.
 */

import { DeclarativeRule, EvidenceItem, RulePredicate } from '../types/contracts';
import { ExtractedFeatures } from './feature-extractor';

export interface EvaluatedRuleOutcome {
  matched: boolean;
  rule_id: string;
  rule_version: string;
  action: 'allow' | 'warn' | 'block';
  severity: 'low' | 'medium' | 'high' | 'critical';
  weight: number;
  evidence: EvidenceItem;
}

export class DeclarativeRuleEvaluator {
  public static evaluateRule(
    rule: DeclarativeRule,
    features: ExtractedFeatures
  ): EvaluatedRuleOutcome | null {
    if (!rule.predicates || rule.predicates.length === 0) {
      return null;
    }

    // All predicates must evaluate to true (logical AND)
    for (const predicate of rule.predicates) {
      if (!this.evaluatePredicate(predicate, features)) {
        return null;
      }
    }

    const evidence: EvidenceItem = {
      rule_id: rule.rule_id,
      description: rule.description || `Matched declarative defensive rule ${rule.rule_id}`,
      severity: rule.severity,
      score_contribution: rule.weight,
      confidence: 0.90,
      metadata: {
        rule_version: rule.rule_version,
        action: rule.action,
      },
    };

    return {
      matched: true,
      rule_id: rule.rule_id,
      rule_version: rule.rule_version,
      action: rule.action,
      severity: rule.severity,
      weight: rule.weight,
      evidence,
    };
  }

  private static evaluatePredicate(
    predicate: RulePredicate,
    features: ExtractedFeatures
  ): boolean {
    const featureVal = features[predicate.field];
    if (featureVal === undefined) {
      return false;
    }

    const targetVal = predicate.value;

    switch (predicate.operator) {
      case 'eq':
        return featureVal === targetVal;

      case 'ne':
        return featureVal !== targetVal;

      case 'gt':
        return typeof featureVal === 'number' && typeof targetVal === 'number' && featureVal > targetVal;

      case 'gte':
        return typeof featureVal === 'number' && typeof targetVal === 'number' && featureVal >= targetVal;

      case 'lt':
        return typeof featureVal === 'number' && typeof targetVal === 'number' && featureVal < targetVal;

      case 'lte':
        return typeof featureVal === 'number' && typeof targetVal === 'number' && featureVal <= targetVal;

      case 'contains':
        if (typeof featureVal === 'string' && typeof targetVal === 'string') {
          return featureVal.includes(targetVal);
        }
        if (Array.isArray(featureVal)) {
          return featureVal.includes(targetVal);
        }
        return false;

      case 'in':
        if (Array.isArray(targetVal)) {
          return (targetVal as Array<unknown>).includes(featureVal);
        }
        if (typeof targetVal === 'string' && typeof featureVal === 'string') {
          return targetVal.includes(featureVal);
        }
        return false;

      case 'matches_regex': {
        if (typeof featureVal !== 'string' || typeof targetVal !== 'string') {
          return false;
        }
        try {
          const re = new RegExp(targetVal);
          return re.test(featureVal);
        } catch {
          return false;
        }
      }

      default:
        return false;
    }
  }
}

