/**
 * CyberDuel AI — Canonical JSON Serialization (RFC 8785 subset)
 * Mirrors packages/shared-contracts/cyberduel_contracts/crypto.py for cross-language consistency.
 */

function normalizeValue(val: unknown): unknown {
  if (val === null || val === undefined) {
    return null;
  }

  if (typeof val === 'number') {
    if (!Number.isFinite(val)) {
      return null;
    }
    return val;
  }

  if (typeof val === 'boolean' || typeof val === 'string') {
    if (typeof val === 'string' && val.endsWith('+00:00')) {
      return val.slice(0, -6) + 'Z';
    }
    return val;
  }

  if (val instanceof Date) {
    return val.toISOString();
  }

  if (Array.isArray(val)) {
    return val.map(normalizeValue);
  }

  if (typeof val === 'object') {
    const record = val as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort();
    const result: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      result[key] = normalizeValue(record[key]);
    }
    return result;
  }

  return String(val);
}

export function canonicalizeJson(data: unknown): Uint8Array {
  const normalized = normalizeValue(data);
  const jsonStr = JSON.stringify(normalized);
  return new TextEncoder().encode(jsonStr);
}

export function getManifestSigningPayload(manifestData: Record<string, unknown>): Uint8Array {
  const payload: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(manifestData)) {
    if (k !== 'signature') {
      payload[k] = v;
    }
  }
  return canonicalizeJson(payload);
}

