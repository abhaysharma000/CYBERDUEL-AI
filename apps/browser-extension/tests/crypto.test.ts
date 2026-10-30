import { describe, expect, it } from 'vitest';
import {
  parseEd25519PublicKeyPem,
  verifyDetachedSignature,
  verifyManifestSignature,
} from '../src/crypto/ed25519';
import { canonicalizeJson } from '../src/crypto/canonical';
import vectors from '../../../datasets/test_vectors/cross_language_vectors.json';

describe('Ed25519 Digital Signature Verification', () => {
  const { public_key_pem, payload, signature_hex } = vectors.crypto_vector;

  it('correctly parses SubjectPublicKeyInfo PEM into 32-byte raw public key', () => {
    const rawKey = parseEd25519PublicKeyPem(public_key_pem);
    expect(rawKey).toBeInstanceOf(Uint8Array);
    expect(rawKey.length).toBe(32);
  });

  it('successfully verifies genuine signature produced by Python backend', () => {
    const dataBytes = canonicalizeJson(payload);
    const isValid = verifyDetachedSignature(public_key_pem, dataBytes, signature_hex);
    expect(isValid).toBe(true);
  });

  it('rejects signature if payload data has been altered', () => {
    const tamperedPayload = { ...payload, sequence_number: 999 };
    const dataBytes = canonicalizeJson(tamperedPayload);
    const isValid = verifyDetachedSignature(public_key_pem, dataBytes, signature_hex);
    expect(isValid).toBe(false);
  });

  it('rejects signature if signature bytes have been corrupted', () => {
    const dataBytes = canonicalizeJson(payload);
    const corruptedSig = signature_hex.substring(0, 60) + 'ff' + signature_hex.substring(62);
    const isValid = verifyDetachedSignature(public_key_pem, dataBytes, corruptedSig);
    expect(isValid).toBe(false);
  });

  it('verifies manifest signature via verifyManifestSignature', () => {
    const manifestWithSig = {
      ...payload,
      signature: signature_hex,
    };
    const isValid = verifyManifestSignature(manifestWithSig, public_key_pem);
    expect(isValid).toBe(true);
  });
});
