import { describe, expect, it } from 'vitest';
import { DNRCompiler } from '../src/dnr/compiler';
import { FACTORY_POLICY_BUNDLE } from '../src/storage/factory-policy';
import { PolicyBundle } from '../src/types/contracts';

describe('DNR Rule Compiler', () => {
  it('compiles block threat indicators into deterministic Chrome dynamic rules', () => {
    const rules = DNRCompiler.compile(FACTORY_POLICY_BUNDLE);

    expect(rules.length).toBeGreaterThan(0);
    const firstRule = rules[0];
    expect(firstRule.id).toBe(DNRCompiler.BASE_RULE_ID);
    expect(firstRule.action.type).toBe('block');
    expect(firstRule.condition.urlFilter).toContain('malicious-phish-portal.test');
    expect(firstRule.condition.resourceTypes).toContain('main_frame');
  });

  it('bounds dynamic rules within MAX_DYNAMIC_RULES quota limit', () => {
    const hugeBundle: PolicyBundle = {
      ...FACTORY_POLICY_BUNDLE,
      threat_indicators: Array.from({ length: 6000 }, (_, i) => ({
        indicator_id: `IND-${i}`,
        type: 'domain',
        value: `bad-domain-${i}.com`,
        hash_sha256: '0'.repeat(64),
        severity: 'critical',
        action: 'block',
        description: `Synthetic threat ${i}`,
      })),
    };

    const rules = DNRCompiler.compile(hugeBundle);
    expect(rules.length).toBe(DNRCompiler.MAX_DYNAMIC_RULES);
  });
});

