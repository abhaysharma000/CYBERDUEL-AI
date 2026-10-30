import { describe, expect, it } from 'vitest';
import { URLNormalizer, URLNormalizationError } from '../src/engine/normalizer';
import vectors from '../../../datasets/test_vectors/cross_language_vectors.json';

describe('URL Normalization and Cross-Language Compatibility', () => {
  it('matches Python URLNormalizer output for all cross-language test vectors', () => {
    for (const v of vectors.normalization_vectors) {
      const norm = URLNormalizer.normalize(v.raw_input);
      expect(norm.scheme).toBe(v.scheme);
      expect(norm.host).toBe(v.host);
      expect(norm.canonical_url).toBe(v.canonical_url);
      expect(norm.domain).toBe(v.domain);
      expect(norm.url_sha256).toBe(v.url_sha256);
      expect(norm.domain_sha256).toBe(v.domain_sha256);
      expect(norm.has_embedded_credentials).toBe(v.has_embedded_credentials);
      expect(norm.is_ip_literal).toBe(v.is_ip_literal);
    }
  });

  it('rejects unsupported URL schemes', () => {
    expect(() => URLNormalizer.normalize('ftp://example.com/file')).toThrowError(URLNormalizationError);
    expect(() => URLNormalizer.normalize('javascript:alert(1)')).toThrowError(URLNormalizationError);
    expect(() => URLNormalizer.normalize('data:text/html,test')).toThrowError(URLNormalizationError);
  });

  it('rejects control characters and null bytes', () => {
    expect(() => URLNormalizer.normalize('http://example.com/\x00test')).toThrowError(URLNormalizationError);
    expect(() => URLNormalizer.normalize('http://example.com/\x07beep')).toThrowError(URLNormalizationError);
  });

  it('rejects URLs exceeding length limits', () => {
    const hugeUrl = 'https://example.com/' + 'a'.repeat(4100);
    expect(() => URLNormalizer.normalize(hugeUrl)).toThrowError(URLNormalizationError);
  });

  it('redacts sensitive query parameters', () => {
    const norm = URLNormalizer.normalize('https://example.com/auth?token=mysecret&api_key=12345&name=bob');
    expect(norm.canonical_url).toContain('api_key=%5BREDACTED%5D');
    expect(norm.canonical_url).toContain('token=%5BREDACTED%5D');
    expect(norm.canonical_url).toContain('name=bob');
  });

  it('redacts embedded credentials from authority', () => {
    const norm = URLNormalizer.normalize('https://admin:supersecret@bank.com/dashboard');
    expect(norm.has_embedded_credentials).toBe(true);
    expect(norm.userinfo).toBe('admin:[REDACTED]');
    expect(norm.canonical_url).toBe('https://bank.com/dashboard');
  });
});
