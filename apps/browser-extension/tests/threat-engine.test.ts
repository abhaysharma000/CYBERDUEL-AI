import { describe, expect, it } from 'vitest';
import { LocalThreatEngine } from '../src/engine/threat-decision';
import { FACTORY_POLICY_BUNDLE } from '../src/storage/factory-policy';

describe('Local Threat Engine Integration', () => {
  const engine = new LocalThreatEngine(FACTORY_POLICY_BUNDLE);

  it('blocks known confirmed threat indicator with threat_intelligence provenance', () => {
    const result = engine.evaluate('https://malicious-phish-portal.test/login');

    expect(result.decision).toBe('block');
    expect(result.risk_score).toBe(1.0);
    expect(result.provenance).toBe('threat_intelligence');
    expect(result.matched_rules).toContain('IND-MALICIOUS-TEST-DOMAIN');
    expect(result.explanation).toContain('Confirmed malicious destination');
  });

  it('blocks embedded credentials via declarative rule with rule_engine provenance', () => {
    const result = engine.evaluate('https://user:password@secure-banking-portal.com/auth');

    expect(result.decision).toBe('block');
    expect(result.provenance).toBe('rule_engine');
    expect(result.matched_rules).toContain('RULE-EMBEDDED-CREDENTIALS');
  });

  it('warns on suspicious brand mimicry heuristics', () => {
    const result = engine.evaluate('https://paypal-portal.com/help');

    expect(result.decision).toBe('warn');
    expect(result.risk_score).toBeGreaterThanOrEqual(0.50);
    expect(result.risk_score).toBeLessThan(0.85);
    expect(result.explanation).toContain('Destination exhibits suspicious indicators');
  });

  it('allows benign destinations with standard benign characteristics', () => {
    const result = engine.evaluate('https://google.com/search?q=cybersecurity');

    expect(result.decision).toBe('allow');
    expect(result.risk_score).toBe(0.0);
    expect(result.explanation).toContain('benign');
  });

  it('reports is_stale: true when active policy is expired', () => {
    const expiredPolicy = {
      ...FACTORY_POLICY_BUNDLE,
      expires_at: '2020-01-01T00:00:00Z',
    };
    const staleEngine = new LocalThreatEngine(expiredPolicy);
    const result = staleEngine.evaluate('https://example.com');

    expect(result.is_stale).toBe(true);
  });
});
