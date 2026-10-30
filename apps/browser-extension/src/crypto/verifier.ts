/**
 * CyberDuel AI — 7-Step Client Update Verifier
 * Implements the mandatory supply-chain security checks on the client edge before activating any policy update.
 */

import { PolicyBundle, ReleaseManifest, TrustAnchorSet } from '../types/contracts';
import { computeSha256 } from './sha256';
import { verifyManifestSignature } from './ed25519';

export interface VerificationResult {
  isValid: boolean;
  stepFailed?: string;
  errorMessage?: string;
  checkpointsPassed: string[];
}

export class ClientUpdateVerifier {
  private currentSequence: number;
  private currentPolicyVersion: string;
  private clientVersion: string;
  private engineVersion: string;

  constructor(options: {
    currentSequence?: number;
    currentPolicyVersion?: string;
    clientVersion?: string;
    engineVersion?: string;
  } = {}) {
    this.currentSequence = options.currentSequence ?? 0;
    this.currentPolicyVersion = options.currentPolicyVersion ?? '0.0.0';
    this.clientVersion = options.clientVersion ?? '1.0.0';
    this.engineVersion = options.engineVersion ?? '1.0.0';
  }

  /**
   * Execute the full 7-step pre-installation pipeline on a downloaded manifest and raw artifact.
   */
  public verify(
    manifest: ReleaseManifest,
    artifactRaw: string | Uint8Array,
    bundle: PolicyBundle,
    trustAnchors: TrustAnchorSet
  ): VerificationResult {
    const passed: string[] = [];

    // Step 1: Trust Anchor & Key Status Verification
    const activeKey = trustAnchors.active_keys.find(
      (k) => k.key_id === manifest.publisher_key_id && k.status === 'active'
    );
    if (!activeKey) {
      return {
        isValid: false,
        stepFailed: 'Step 1: Trust Anchor Verification',
        errorMessage: `Publisher key '${manifest.publisher_key_id}' is not in active trust anchors.`,
        checkpointsPassed: passed,
      };
    }

    const isRevoked = trustAnchors.revoked_keys.some((k) => k.key_id === manifest.publisher_key_id);
    if (isRevoked) {
      return {
        isValid: false,
        stepFailed: 'Step 1: Trust Anchor Verification',
        errorMessage: `Publisher key '${manifest.publisher_key_id}' has been revoked.`,
        checkpointsPassed: passed,
      };
    }
    passed.push('Step 1: Trust Anchor Verification');

    // Step 2: Digital Signature Verification
    const manifestDict = manifest as unknown as Record<string, unknown>;
    const signatureValid = verifyManifestSignature(manifestDict, activeKey.public_key_pem);
    if (!signatureValid) {
      return {
        isValid: false,
        stepFailed: 'Step 2: Digital Signature Verification',
        errorMessage: 'Ed25519 digital signature verification failed over canonical manifest.',
        checkpointsPassed: passed,
      };
    }
    passed.push('Step 2: Digital Signature Verification');

    // Step 3: Anti-Replay Monotonic Sequence Ordering
    if (!manifest.is_rollback) {
      if (manifest.sequence_number <= this.currentSequence) {
        return {
          isValid: false,
          stepFailed: 'Step 3: Anti-Replay Sequence Ordering',
          errorMessage: `Sequence ${manifest.sequence_number} is not strictly greater than current ${this.currentSequence}.`,
          checkpointsPassed: passed,
        };
      }
    } else {
      // In rollback mode, sequence must still be strictly higher than current to avoid rollback replays
      if (manifest.sequence_number <= this.currentSequence) {
        return {
          isValid: false,
          stepFailed: 'Step 3: Anti-Replay Sequence Ordering (Rollback)',
          errorMessage: `Rollback sequence ${manifest.sequence_number} must exceed current sequence ${this.currentSequence}.`,
          checkpointsPassed: passed,
        };
      }
    }
    passed.push('Step 3: Anti-Replay Sequence Ordering');

    // Step 4: Client & Engine Version Compatibility
    if (manifest.supported_platforms && !manifest.supported_platforms.includes('browser_extension')) {
      return {
        isValid: false,
        stepFailed: 'Step 4: Platform Compatibility',
        errorMessage: "Release manifest does not support 'browser_extension' platform.",
        checkpointsPassed: passed,
      };
    }
    // Simple semver compare: client version must satisfy min_client_version
    if (this.compareSemver(this.clientVersion, manifest.min_client_version) < 0) {
      return {
        isValid: false,
        stepFailed: 'Step 4: Version Compatibility',
        errorMessage: `Client version ${this.clientVersion} is below minimum required ${manifest.min_client_version}.`,
        checkpointsPassed: passed,
      };
    }
    if (this.compareSemver(this.engineVersion, manifest.min_engine_version) < 0) {
      return {
        isValid: false,
        stepFailed: 'Step 4: Version Compatibility',
        errorMessage: `Engine version ${this.engineVersion} is below minimum required ${manifest.min_engine_version}.`,
        checkpointsPassed: passed,
      };
    }
    if (manifest.is_rollback && manifest.rollback_target_version) {
      if (manifest.rollback_target_version === this.currentPolicyVersion) {
        // Target is already the current version
      }
    }
    passed.push('Step 4: Version Compatibility');

    // Step 5: Expiration Cutoff Check
    const expiresAtMs = new Date(manifest.expires_at).getTime();
    if (Date.now() > expiresAtMs) {
      return {
        isValid: false,
        stepFailed: 'Step 5: Expiration Check',
        errorMessage: `Release manifest expired at ${manifest.expires_at}.`,
        checkpointsPassed: passed,
      };
    }
    passed.push('Step 5: Expiration Check');

    // Step 6: Artifact Digest Verification
    const computedDigest =
      typeof artifactRaw === 'string'
        ? computeSha256(new TextEncoder().encode(artifactRaw))
        : computeSha256(artifactRaw);

    if (computedDigest.toLowerCase() !== manifest.artifact_digest.toLowerCase()) {
      return {
        isValid: false,
        stepFailed: 'Step 6: Artifact Integrity',
        errorMessage: `Artifact digest mismatch. Expected ${manifest.artifact_digest}, computed ${computedDigest}.`,
        checkpointsPassed: passed,
      };
    }
    passed.push('Step 6: Artifact Integrity');

    // Step 7: Bundle Schema and Declarative AST Safety
    const safetyResult = this.verifyBundleSafety(bundle);
    if (!safetyResult.isValid) {
      return {
        isValid: false,
        stepFailed: 'Step 7: Bundle Safety Check',
        errorMessage: safetyResult.errorMessage,
        checkpointsPassed: passed,
      };
    }
    passed.push('Step 7: Bundle Safety Check');

    return {
      isValid: true,
      checkpointsPassed: passed,
    };
  }

  private verifyBundleSafety(bundle: PolicyBundle): { isValid: boolean; errorMessage?: string } {
    if (!bundle.policy_version || !bundle.rules || !Array.isArray(bundle.rules)) {
      return { isValid: false, errorMessage: 'Malformed bundle: missing policy_version or rules list.' };
    }

    const ALLOWED_OPERATORS = new Set([
      'eq',
      'ne',
      'gt',
      'gte',
      'lt',
      'lte',
      'contains',
      'in',
      'matches_regex',
    ]);

    for (const rule of bundle.rules) {
      if (!rule.rule_id || !rule.predicates || rule.predicates.length === 0) {
        return { isValid: false, errorMessage: `Rule ${rule.rule_id || 'unknown'} has no predicates.` };
      }

      if (rule.predicates.length > 10) {
        return {
          isValid: false,
          errorMessage: `Rule ${rule.rule_id} exceeds maximum predicate limit of 10.`,
        };
      }

      for (const pred of rule.predicates) {
        if (!ALLOWED_OPERATORS.has(pred.operator)) {
          return {
            isValid: false,
            errorMessage: `Rule ${rule.rule_id} contains forbidden operator '${pred.operator}'.`,
          };
        }

        if (pred.operator === 'matches_regex') {
          const pattern = String(pred.value);
          if (pattern.length > 128) {
            return {
              isValid: false,
              errorMessage: `Regex in rule ${rule.rule_id} exceeds 128 characters.`,
            };
          }
          try {
            new RegExp(pattern);
          } catch {
            return {
              isValid: false,
              errorMessage: `Invalid regex pattern in rule ${rule.rule_id}: ${pattern}`,
            };
          }
        }
      }
    }

    return { isValid: true };
  }

  private compareSemver(v1: string, v2: string): number {
    const p1 = v1.split('.').map((n) => parseInt(n, 10) || 0);
    const p2 = v2.split('.').map((n) => parseInt(n, 10) || 0);
    for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
      const a = p1[i] || 0;
      const b = p2[i] || 0;
      if (a > b) return 1;
      if (a < b) return -1;
    }
    return 0;
  }
}
