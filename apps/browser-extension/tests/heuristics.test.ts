import { describe, expect, it } from 'vitest';
import { URLNormalizer } from '../src/engine/normalizer';
import { URLFeatureExtractor } from '../src/engine/feature-extractor';
import { HeuristicAnalyzer } from '../src/engine/heuristics';

describe('Heuristic Threat Analyzer', () => {
  it('detects brand impersonation on unofficial domains', () => {
    const norm = URLNormalizer.normalize('https://paypal-verify-account.suspicious.com/login');
    const features = URLFeatureExtractor.extract(norm);
    const result = HeuristicAnalyzer.analyze(features);

    expect(features.brand_token_detected).toBe(true);
    expect(result.heuristicScore).toBeGreaterThanOrEqual(0.65);
    const brandEvidence = result.evidence.find((e) => e.rule_id === 'HEUR-BRAND-IMPERSONATION');
    expect(brandEvidence).toBeDefined();
  });

  it('does NOT flag official brand domains as brand impersonation', () => {
    const norm = URLNormalizer.normalize('https://www.paypal.com/signin');
    const features = URLFeatureExtractor.extract(norm);
    const result = HeuristicAnalyzer.analyze(features);

    expect(features.brand_token_detected).toBe(false);
    const brandEvidence = result.evidence.find((e) => e.rule_id === 'HEUR-BRAND-IMPERSONATION');
    expect(brandEvidence).toBeUndefined();
  });

  it('bypasses heuristics for verified top trusted domains', () => {
    const norm = URLNormalizer.normalize('https://github.com/login');
    const features = URLFeatureExtractor.extract(norm);
    const result = HeuristicAnalyzer.analyze(features);

    expect(features.is_whitelisted).toBe(true);
    expect(result.heuristicScore).toBe(0.0);
    expect(result.evidence[0].rule_id).toBe('HEUR-WHITELIST-TOP-DOMAIN');
  });

  it('flags raw IP literal hosts', () => {
    const norm = URLNormalizer.normalize('http://192.168.1.1:8080/admin');
    const features = URLFeatureExtractor.extract(norm);
    const result = HeuristicAnalyzer.analyze(features);

    expect(features.is_ip_literal).toBe(true);
    const ipEvidence = result.evidence.find((e) => e.rule_id === 'HEUR-IP-LITERAL-HOST');
    expect(ipEvidence).toBeDefined();
  });

  it('flags suspicious TLDs with elevated abuse history', () => {
    const norm = URLNormalizer.normalize('http://free-reward-portal.tk/claim');
    const features = URLFeatureExtractor.extract(norm);
    const result = HeuristicAnalyzer.analyze(features);

    const tldEvidence = result.evidence.find((e) => e.rule_id === 'HEUR-SUSPICIOUS-TLD');
    expect(tldEvidence).toBeDefined();
  });
});

