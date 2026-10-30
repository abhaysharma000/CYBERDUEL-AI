import { describe, expect, it } from 'vitest';
import { DeclarativeRuleEvaluator } from '../src/engine/rule-evaluator';
import { DeclarativeRule } from '../src/types/contracts';
import { ExtractedFeatures } from '../src/engine/feature-extractor';

describe('Declarative AST Rule Evaluator', () => {
  const sampleFeatures: ExtractedFeatures = {
    url_length: 50,
    host_length: 20,
    path_length: 15,
    query_length: 10,
    subdomain_count: 2,
    path_depth: 3,
    has_embedded_credentials: true,
    is_ip_literal: false,
    is_punycode: false,
    brand_token_detected: true,
    has_non_standard_port: false,
    phish_keyword_count: 2,
    host_entropy: 3.8,
    scheme: 'https',
    host: 'paypal-login.suspicious.com',
    unicode_host: 'paypal-login.suspicious.com',
    port: 443,
    domain: 'suspicious.com',
    is_whitelisted: false,
  };

  it('evaluates eq, gt, and contains operators correctly', () => {
    const rule: DeclarativeRule = {
      rule_id: 'TEST-RULE-01',
      rule_version: '1.0.0',
      name: 'Credentials and Brand Check',
      description: 'Matches embedded credentials with brand token',
      severity: 'critical',
      action: 'block',
      predicates: [
        { field: 'has_embedded_credentials', operator: 'eq', value: true },
        { field: 'phish_keyword_count', operator: 'gt', value: 1 },
        { field: 'host', operator: 'contains', value: 'paypal' },
      ],
      weight: 0.95,
    };

    const outcome = DeclarativeRuleEvaluator.evaluateRule(rule, sampleFeatures);
    expect(outcome).not.toBeNull();
    expect(outcome?.matched).toBe(true);
    expect(outcome?.action).toBe('block');
    expect(outcome?.evidence.rule_id).toBe('TEST-RULE-01');
  });

  it('fails match when a predicate does not satisfy condition', () => {
    const rule: DeclarativeRule = {
      rule_id: 'TEST-RULE-02',
      rule_version: '1.0.0',
      name: 'Punycode Check',
      description: 'Checks punycode',
      severity: 'high',
      action: 'warn',
      predicates: [
        { field: 'is_punycode', operator: 'eq', value: true }, // false in sampleFeatures
      ],
      weight: 0.60,
    };

    const outcome = DeclarativeRuleEvaluator.evaluateRule(rule, sampleFeatures);
    expect(outcome).toBeNull();
  });

  it('evaluates matches_regex operator safely', () => {
    const rule: DeclarativeRule = {
      rule_id: 'TEST-RULE-REGEX',
      rule_version: '1.0.0',
      name: 'Regex Domain Matcher',
      description: 'Regex over domain',
      severity: 'medium',
      action: 'warn',
      predicates: [
        { field: 'domain', operator: 'matches_regex', value: '^suspicious\\.(com|org)$' },
      ],
      weight: 0.50,
    };

    const outcome = DeclarativeRuleEvaluator.evaluateRule(rule, sampleFeatures);
    expect(outcome).not.toBeNull();
    expect(outcome?.matched).toBe(true);
  });
});

