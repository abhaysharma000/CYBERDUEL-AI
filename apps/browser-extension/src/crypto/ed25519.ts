/**
 * CyberDuel AI — Ed25519 Digital Signature Verification
 * Parses SubjectPublicKeyInfo PEM keys and performs high-assurance Ed25519 verification.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { getManifestSigningPayload } from './canonical';

/**
 * Convert a hexadecimal string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.trim().replace(/^0x/i, '');
  if (cleanHex.length % 2 !== 0) {
    throw new Error(`Invalid hexadecimal string length: ${cleanHex.length}`);
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    const byte = parseInt(cleanHex.substring(i, i + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`Invalid hexadecimal character at position ${i}`);
    }
    bytes[i / 2] = byte;
  }
  return bytes;
}

/**
 * Decode Base64 string to Uint8Array in standard browser and Node environments.
 */
export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/[\r\n\s]/g, '');
  if (typeof atob === 'function') {
    const binStr = atob(clean);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }
    return bytes;
  }
  // Node fallback if atob is unavailable
  return Uint8Array.from(Buffer.from(clean, 'base64'));
}

/**
 * Extract raw 32-byte Ed25519 public key from a SubjectPublicKeyInfo PEM string.
 * SubjectPublicKeyInfo for Ed25519 is 44 bytes in DER:
 * 12-byte header (302a300506032b6570032100) + 32-byte raw public key.
 */
export function parseEd25519PublicKeyPem(pem: string): Uint8Array {
  const lines = pem
    .split(/\r?\n/)
    .filter((line) => !line.startsWith('-----') && line.trim().length > 0);
  const b64 = lines.join('');
  const der = base64ToBytes(b64);

  if (der.length === 32) {
    // Raw 32-byte key provided
    return der;
  }

  if (der.length === 44) {
    // Standard RFC 8410 SubjectPublicKeyInfo for Ed25519
    return der.slice(12, 44);
  }

  if (der.length > 32) {
    // Fallback: take the final 32 bytes of the BIT STRING
    return der.slice(der.length - 32);
  }

  throw new Error(`Invalid Ed25519 public key length: ${der.length} bytes (expected 32 or 44)`);
}

/**
 * Verify detached Ed25519 signature against arbitrary data bytes.
 */
export function verifyDetachedSignature(
  publicKeyPem: string,
  data: Uint8Array,
  signatureHex: string
): boolean {
  try {
    const rawPublicKey = parseEd25519PublicKeyPem(publicKeyPem);
    const signatureBytes = hexToBytes(signatureHex);

    if (signatureBytes.length !== 64) {
      return false;
    }

    return ed25519.verify(signatureBytes, data, rawPublicKey);
  } catch {
    return false;
  }
}

/**
 * Verify release manifest digital signature.
 */
export function verifyManifestSignature(
  manifestData: Record<string, unknown>,
  publicKeyPem: string
): boolean {
  const signature = manifestData.signature;
  if (typeof signature !== 'string' || !signature) {
    return false;
  }

  const payloadBytes = getManifestSigningPayload(manifestData);
  return verifyDetachedSignature(publicKeyPem, payloadBytes, signature);
}

