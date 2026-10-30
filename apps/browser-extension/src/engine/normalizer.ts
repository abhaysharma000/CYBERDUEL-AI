/**
 * CyberDuel AI — Client-Side URL Normalizer
 * Implements strict RFC 3986 / WHATWG parsing, credential redaction, and canonicalization.
 * 100% compatible with packages/threat-intelligence/cyberduel_threat_intel/normalizer.py.
 */

import { NormalizedURLData } from '../types/contracts';
import { computeSha256 } from '../crypto/sha256';

export const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'access_token',
  'auth',
  'key',
  'apikey',
  'api_key',
  'password',
  'passwd',
  'secret',
  'session',
  'sessionid',
  'session_id',
  'jwt',
  'bearer',
  'code',
  'pin',
  'otp',
]);

export const SUPPORTED_SCHEMES = new Set(['http', 'https']);

export class URLNormalizationError extends Error {
  public code: string;

  constructor(message: string, code = 'INVALID_URL') {
    super(message);
    this.name = 'URLNormalizationError';
    this.code = code;
  }
}

export class URLNormalizer {
  public static readonly MAX_URL_LENGTH = 4096;
  public static readonly MAX_HOST_LENGTH = 253;

  public static normalize(rawInput: string): NormalizedURLData {
    if (typeof rawInput !== 'string') {
      throw new URLNormalizationError('URL input must be a string.', 'INVALID_TYPE');
    }

    const cleaned = rawInput.trim();
    if (!cleaned) {
      throw new URLNormalizationError('URL input cannot be empty.', 'EMPTY_INPUT');
    }

    if (cleaned.length > this.MAX_URL_LENGTH) {
      throw new URLNormalizationError(
        `URL exceeds maximum allowed length of ${this.MAX_URL_LENGTH} characters.`,
        'URL_TOO_LONG'
      );
    }

    // Check for control characters
    for (let i = 0; i < cleaned.length; i++) {
      const code = cleaned.charCodeAt(i);
      if (code < 32 || code === 127) {
        throw new URLNormalizationError(
          'URL contains forbidden ASCII control characters or null bytes.',
          'CONTROL_CHARACTERS'
        );
      }
    }

    let parsed: URL;
    try {
      parsed = new URL(cleaned);
    } catch (err) {
      throw new URLNormalizationError(`URL parsing failed: ${err}`, 'PARSE_ERROR');
    }

    // 1. Validate Scheme
    const rawScheme = parsed.protocol.replace(':', '').toLowerCase();
    if (!SUPPORTED_SCHEMES.has(rawScheme)) {
      throw new URLNormalizationError(
        `Unsupported URL scheme '${rawScheme}'. Only http and https are permitted.`,
        'UNSUPPORTED_SCHEME'
      );
    }
    const scheme = rawScheme;

    // 2. Credentials Handling
    let hasEmbeddedCredentials = false;
    let userinfo: string | null = null;
    if (parsed.username || parsed.password) {
      hasEmbeddedCredentials = true;
      userinfo = parsed.password ? `${parsed.username}:[REDACTED]` : parsed.username;
    }

    // 3. Host and Port Normalization
    let host = parsed.hostname.toLowerCase().replace(/\.+$/, '');
    if (!host) {
      throw new URLNormalizationError('URL authority/hostname is missing.', 'MISSING_HOSTNAME');
    }

    if (host.length > this.MAX_HOST_LENGTH) {
      throw new URLNormalizationError(
        `Hostname exceeds maximum length of ${this.MAX_HOST_LENGTH} characters.`,
        'HOST_TOO_LONG'
      );
    }

    // Check for IP literal
    const isIpV4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
    const isIpV6 = host.startsWith('[') && host.endsWith(']');
    const isIpLiteral = isIpV4 || isIpV6;

    // Punycode & IDN
    let isPunycode = false;
    let unicodeHost = host;
    if (!isIpLiteral) {
      if (host.startsWith('xn--') || host.includes('.xn--')) {
        isPunycode = true;
        // In browser/node, we can keep the punycode or decode if URL parser decoded
      }
    }

    // Port
    let port: number | null = null;
    if (parsed.port) {
      const portVal = parseInt(parsed.port, 10);
      if (Number.isNaN(portVal) || portVal < 1 || portVal > 65535) {
        throw new URLNormalizationError(`Port out of range [1-65535]: ${parsed.port}`, 'PORT_OUT_OF_RANGE');
      }
      if ((scheme === 'http' && portVal !== 80) || (scheme === 'https' && portVal !== 443)) {
        port = portVal;
      }
    }

    // 4. Domain and Subdomain Extraction
    const { domain, subdomains } = this.extractDomainAndSubdomains(host, isIpLiteral);

    // 5. Path Normalization (resolve dot segments)
    const rawPath = parsed.pathname || '/';
    const normalizedPath = this.normalizePath(rawPath);

    // 6. Query Normalization & Sensitive Parameter Redaction
    let normalizedQuery: string | null = null;
    if (parsed.search && parsed.search.length > 1) {
      normalizedQuery = this.normalizeQuery(parsed.search.slice(1));
    }

    // 7. Fragment
    const fragment = parsed.hash ? parsed.hash.slice(1) : null;

    // 8. Canonical URL Construction
    const portStr = port !== null ? `:${port}` : '';
    const queryStr = normalizedQuery !== null ? `?${normalizedQuery}` : '';
    const canonicalUrl = `${scheme}://${host}${portStr}${normalizedPath}${queryStr}`;

    // 9. Cryptographic Digests
    const urlSha256 = computeSha256(canonicalUrl);
    const domainSha256 = computeSha256(domain);

    return {
      raw_input: cleaned,
      scheme,
      host,
      unicode_host: unicodeHost,
      port,
      path: normalizedPath,
      query: normalizedQuery,
      fragment,
      canonical_url: canonicalUrl,
      domain,
      subdomains,
      url_sha256: urlSha256,
      domain_sha256: domainSha256,
      has_embedded_credentials: hasEmbeddedCredentials,
      userinfo,
      is_ip_literal: isIpLiteral,
      is_punycode: isPunycode,
    };
  }

  private static extractDomainAndSubdomains(
    host: string,
    isIpLiteral: boolean
  ): { domain: string; subdomains: string[] } {
    if (isIpLiteral) {
      return { domain: host, subdomains: [] };
    }

    const parts = host.split('.');
    if (parts.length <= 1) {
      return { domain: host, subdomains: [] };
    }

    // Multi-part TLD detection (e.g. .co.uk, .com.au, .gov.uk)
    const secondLevelTlds = new Set(['co', 'com', 'org', 'net', 'edu', 'gov', 'mil', 'ac']);
    let domain: string;
    let subdomains: string[];

    if (parts.length >= 3 && secondLevelTlds.has(parts[parts.length - 2])) {
      domain = parts.slice(-3).join('.');
      subdomains = parts.slice(0, -3);
    } else {
      domain = parts.slice(-2).join('.');
      subdomains = parts.slice(0, -2);
    }

    return { domain, subdomains };
  }

  private static normalizePath(rawPath: string): string {
    // Resolve RFC 3986 dot segments
    const segments = rawPath.split('/');
    const output: string[] = [];

    for (const segment of segments) {
      if (segment === '' || segment === '.') {
        continue;
      }
      if (segment === '..') {
        if (output.length > 0) {
          output.pop();
        }
      } else {
        output.push(segment);
      }
    }

    const resolved = '/' + output.join('/');
    return rawPath.endsWith('/') && !resolved.endsWith('/') ? resolved + '/' : resolved;
  }

  private static normalizeQuery(search: string): string {
    const params = new URLSearchParams(search);
    const sortedEntries: Array<[string, string]> = [];

    for (const [key, value] of params.entries()) {
      const lowerKey = key.toLowerCase();
      if (SENSITIVE_QUERY_PARAMS.has(lowerKey)) {
        sortedEntries.push([key, '[REDACTED]']);
      } else {
        sortedEntries.push([key, value]);
      }
    }

    sortedEntries.sort((a, b) => a[0].localeCompare(b[0]));
    const resultParams = new URLSearchParams();
    for (const [k, v] of sortedEntries) {
      resultParams.append(k, v);
    }
    return resultParams.toString();
  }
}

