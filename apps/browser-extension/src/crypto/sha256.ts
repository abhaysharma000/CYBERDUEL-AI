/**
 * CyberDuel AI — SHA-256 Digest Utilities
 * Uses @noble/hashes for fast, synchronous, standard RFC 6234 SHA-256 calculation.
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { canonicalizeJson } from './canonical';

export function computeSha256(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = sha256(bytes);
  return bytesToHex(hash);
}

export function computeCanonicalSha256(data: unknown): string {
  const canonicalBytes = canonicalizeJson(data);
  return computeSha256(canonicalBytes);
}

