import { describe, expect, it } from 'vitest';
import { ClientUpdateVerifier } from '../src/crypto/verifier';
import {
  PolicyBundle,
  ReleaseManifest,
  TrustAnchorSet,
} from '../src/types/contracts';
import { FACTORY_POLICY_BUNDLE } from '../src/storage/factory-policy';
import vectors from '../../../datasets/test_vectors/cross_language_vectors.json';

describe('7-Step Client Update Verifier Pipeline', () => {
  const { public_key_pem, payload } = vectors.crypto_vector;

  const validTrustAnchors: TrustAnchorSet = {
    active_keys: [
      {
        key_id: payload.publisher_key_id,
        algorithm: 'ed25519',
        public_key_pem: public_key_pem,
        status: 'active',
        valid_from: '2026-01-01T00:00:00Z',
      },
    ],
    revoked_keys: [],
    timestamp: '2026-10-29T00:00:00Z',
  };

  const sampleRawArtifact = vectors.crypto_vector.sample_raw_artifact;
  const sampleManifest: ReleaseManifest = vectors.crypto_vector.full_manifest as unknown as ReleaseManifest;

  const sampleBundle: PolicyBundle = {
    ...FACTORY_POLICY_BUNDLE,
    policy_version: payload.policy_version,
    sequence_number: payload.sequence_number,
  };

  it('passes all 7 verification checkpoints for a genuine signed release', () => {
    const verifier = new ClientUpdateVerifier({
      currentSequence: 10, // Below manifest sequence 42
      clientVersion: '1.0.0',
      engineVersion: '1.0.0',
    });

    const result = verifier.verify(
      sampleManifest,
      sampleRawArtifact,
      sampleBundle,
      validTrustAnchors
    );

    expect(result.isValid).toBe(true);
    expect(result.checkpointsPassed.length).toBe(7);
  });

  it('fails Step 1 when publisher key is not in active trust anchors', () => {
    const verifier = new ClientUpdateVerifier({ currentSequence: 10 });
    const emptyTrustAnchors: TrustAnchorSet = {
      active_keys: [],
      revoked_keys: [],
      timestamp: '2026-10-29T00:00:00Z',
    };

    const result = verifier.verify(
      sampleManifest,
      sampleRawArtifact,
      sampleBundle,
      emptyTrustAnchors
    );

    expect(result.isValid).toBe(false);
    expect(result.stepFailed).toContain('Step 1');
    expect(result.errorMessage).toContain('not in active trust anchors');
  });

  it('fails Step 1 when publisher key is revoked', () => {
    const verifier = new ClientUpdateVerifier({ currentSequence: 10 });
    const revokedTrustAnchors: TrustAnchorSet = {
      active_keys: validTrustAnchors.active_keys,
      revoked_keys: [validTrustAnchors.active_keys[0]],
      timestamp: '2026-10-29T00:00:00Z',
    };

    const result = verifier.verify(
      sampleManifest,
      sampleRawArtifact,
      sampleBundle,
      revokedTrustAnchors
    );

    expect(result.isValid).toBe(false);
    expect(result.stepFailed).toContain('Step 1');
    expect(result.errorMessage).toContain('has been revoked');
  });

  it('fails Step 2 when manifest payload is tampered', () => {
    const verifier = new ClientUpdateVerifier({ currentSequence: 10 });
    const tamperedManifest = {
      ...sampleManifest,
      policy_version: '2026.10.999-tampered',
    };

    const result = verifier.verify(
      tamperedManifest,
      sampleRawArtifact,
      sampleBundle,
      validTrustAnchors
    );

    expect(result.isValid).toBe(false);
    expect(result.stepFailed).toContain('Step 2');
    expect(result.errorMessage).toContain('signature verification failed');
  });

  it('fails Step 3 when sequence number is replayed (not strictly greater)', () => {
    const verifier = new ClientUpdateVerifier({
      currentSequence: 50, // Higher than manifest sequence 42
    });

    const result = verifier.verify(
      sampleManifest,
      sampleRawArtifact,
      sampleBundle,
      validTrustAnchors
    );

    expect(result.isValid).toBe(false);
    expect(result.stepFailed).toContain('Step 3');
    expect(result.errorMessage).toContain('not strictly greater');
  });

  it('fails Step 4 when client version is below required minimum', () => {
    const verifier = new ClientUpdateVerifier({
      currentSequence: 10,
      clientVersion: '0.0.5', // Lower than min_client_version 0.1.0
    });

    const result = verifier.verify(
      sampleManifest,
      sampleRawArtifact,
      sampleBundle,
      validTrustAnchors
    );

    expect(result.isValid).toBe(false);
    expect(result.stepFailed).toContain('Step 4');
  });

  it('fails Step 5 when release manifest is expired', () => {
    // Fast-forward time past manifest expiration (2028-12-31)
    const originalNow = Date.now;
    try {
      Date.now = () => new Date('2029-01-01T00:00:00Z').getTime();
      const verifier = new ClientUpdateVerifier({ currentSequence: 10 });

      const result = verifier.verify(
        sampleManifest,
        sampleRawArtifact,
        sampleBundle,
        validTrustAnchors
      );

      expect(result.isValid).toBe(false);
      expect(result.stepFailed).toContain('Step 5');
      expect(result.errorMessage).toContain('expired');
    } finally {
      Date.now = originalNow;
    }
  });

  it('fails Step 6 when artifact digest does not match downloaded bytes', () => {
    const verifier = new ClientUpdateVerifier({ currentSequence: 10 });
    const corruptedArtifact = 'corrupted or altered policy bytes';

    const result = verifier.verify(
      sampleManifest,
      corruptedArtifact,
      sampleBundle,
      validTrustAnchors
    );

    expect(result.isValid).toBe(false);
    expect(result.stepFailed).toContain('Step 6');
    expect(result.errorMessage).toContain('Artifact digest mismatch');
  });

  it('fails Step 7 when bundle contains malformed or unbounded rules', () => {
    const verifier = new ClientUpdateVerifier({ currentSequence: 10 });
    const unsafeBundle: PolicyBundle = {
      ...sampleBundle,
      rules: [
        {
          rule_id: 'UNSAFE-RULE',
          rule_version: '1.0.0',
          name: 'Unsafe Regex',
          description: 'Unbounded regex',
          severity: 'high',
          action: 'warn',
          predicates: [
            {
              field: 'host',
              operator: 'matches_regex',
              value: 'a'.repeat(200), // Exceeds 128-char limit
            },
          ],
          weight: 0.5,
        },
      ],
    };

    const result = verifier.verify(
      sampleManifest,
      sampleRawArtifact,
      unsafeBundle,
      validTrustAnchors
    );

    expect(result.isValid).toBe(false);
    expect(result.stepFailed).toContain('Step 7');
    expect(result.errorMessage).toContain('exceeds 128 characters');
  });
});
