import { describe, expect, it } from 'vitest';
import { canonicalizeJson, getManifestSigningPayload } from '../src/crypto/canonical';
import vectors from '../../../datasets/test_vectors/cross_language_vectors.json';

describe('Canonical JSON Serialization (RFC 8785 subset)', () => {
  it('recursively sorts object keys lexicographically with compact delimiters', () => {
    const input = {
      z: 1,
      a: 'hello',
      nested: {
        b: true,
        a: false,
      },
      arr: [3, 2, 1],
    };

    const bytes = canonicalizeJson(input);
    const jsonStr = new TextDecoder().decode(bytes);

    expect(jsonStr).toBe('{"a":"hello","arr":[3,2,1],"nested":{"a":false,"b":true},"z":1}');
  });

  it('normalizes UTC timestamps with +00:00 to Z suffix', () => {
    const input = {
      published_at: '2026-10-29T12:00:00+00:00',
    };
    const bytes = canonicalizeJson(input);
    const jsonStr = new TextDecoder().decode(bytes);

    expect(jsonStr).toBe('{"published_at":"2026-10-29T12:00:00Z"}');
  });

  it('matches canonical serialization produced by Python cyberduel_contracts.crypto', () => {
    const pythonPayload = vectors.crypto_vector.payload;
    const expectedStr = vectors.crypto_vector.canonical_json_str;

    const tsBytes = canonicalizeJson(pythonPayload);
    const tsStr = new TextDecoder().decode(tsBytes);

    expect(tsStr).toBe(expectedStr);
  });

  it('extracts manifest signing payload excluding the signature field', () => {
    const manifest = {
      policy_version: '2026.10.1',
      sequence_number: 10,
      signature: '1234567890abcdef',
    };
    const payloadBytes = getManifestSigningPayload(manifest);
    const jsonStr = new TextDecoder().decode(payloadBytes);

    expect(jsonStr).toBe('{"policy_version":"2026.10.1","sequence_number":10}');
    expect(jsonStr).not.toContain('signature');
  });
});
