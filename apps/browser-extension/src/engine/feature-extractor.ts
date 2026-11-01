/**
 * CyberDuel AI — Deterministic Feature Extractor
 * Extracts structural and lexical metrics from NormalizedURLData for rule and heuristic evaluation.
 */

import { NormalizedURLData } from '../types/contracts';

export interface ExtractedFeatures {
  url_length: number;
  host_length: number;
  path_length: number;
  query_length: number;
  subdomain_count: number;
  path_depth: number;
  has_embedded_credentials: boolean;
  is_ip_literal: boolean;
  is_punycode: boolean;
  brand_token_detected: boolean;
  has_non_standard_port: boolean;
  phish_keyword_count: number;
  host_entropy: number;
  scheme: string;
  host: string;
  unicode_host: string;
  port: number;
  domain: string;
  is_whitelisted: boolean;
  [key: string]: string | number | boolean;
}

export const HIGH_VALUE_BRANDS = new Set([
  'paypal',
  'microsoft',
  'apple',
  'google',
  'netflix',
  'amazon',
  'chase',
  'wellsfargo',
  'bankofamerica',
  'binance',
  'coinbase',
  'dropbox',
  'facebook',
  'instagram',
  'linkedin',
  'adobe',
  'docusign',
  'freefire',
  'roblox',
  'steam',
  'discord',
  'telegram',
  'whatsapp',
]);

export const OFFICIAL_BRAND_DOMAINS: Record<string, Set<string>> = {
  paypal: new Set(['paypal.com', 'paypal.me']),
  microsoft: new Set(['microsoft.com', 'live.com', 'office.com', 'azure.com']),
  apple: new Set(['apple.com', 'icloud.com']),
  google: new Set(['google.com', 'gmail.com', 'youtube.com']),
  netflix: new Set(['netflix.com']),
  amazon: new Set(['amazon.com', 'aws.amazon.com']),
  chase: new Set(['chase.com']),
  wellsfargo: new Set(['wellsfargo.com']),
  bankofamerica: new Set(['bankofamerica.com']),
  binance: new Set(['binance.com']),
  coinbase: new Set(['coinbase.com']),
  dropbox: new Set(['dropbox.com']),
  facebook: new Set(['facebook.com', 'meta.com']),
  instagram: new Set(['instagram.com']),
  linkedin: new Set(['linkedin.com']),
  adobe: new Set(['adobe.com']),
  docusign: new Set(['docusign.com']),
  freefire: new Set(['garena.com', 'ff.garena.com', 'freefiremobile.com']),
  roblox: new Set(['roblox.com']),
  steam: new Set(['steampowered.com', 'steamcommunity.com']),
  discord: new Set(['discord.com', 'discord.gg']),
  telegram: new Set(['telegram.org', 't.me']),
  whatsapp: new Set(['whatsapp.com']),
};

export const TRUSTED_TOP_DOMAINS = new Set([
  'google.com',
  'apple.com',
  'microsoft.com',
  'amazon.com',
  'github.com',
  'wikipedia.org',
  'cloudflare.com',
  'mozilla.org',
  'python.org',
  'w3.org',
  'eff.org',
  'nist.gov',
]);

export const PHISHING_KEYWORDS = new Set([
  'login',
  'signin',
  'verify',
  'verification',
  'account-update',
  'security-check',
  'confirm-identity',
  'wallet-connect',
  'billing-update',
  'password-reset',
  'secure-banking',
  'mod-apk',
  'cracked-apk',
  'aimbot',
  'free-diamonds',
  'hack-tool',
]);

export class URLFeatureExtractor {
  public static extract(url: NormalizedURLData): ExtractedFeatures {
    const hostEntropy = this.calculateEntropy(url.host);

    // Path depth
    const pathSegments = url.path.split('/').filter((s) => s.length > 0);
    const pathDepth = pathSegments.length;

    // Check brand token impersonation
    let brandDetected = false;
    for (const brand of HIGH_VALUE_BRANDS) {
      if (url.host.includes(brand)) {
        const officialSet = OFFICIAL_BRAND_DOMAINS[brand];
        if (!officialSet || !officialSet.has(url.domain)) {
          brandDetected = true;
          break;
        }
      }
    }

    // Phishing keywords count
    const fullText = `${url.host} ${url.path} ${url.query || ''}`.toLowerCase();
    let keywordCount = 0;
    for (const kw of PHISHING_KEYWORDS) {
      if (fullText.includes(kw)) {
        keywordCount++;
      }
    }

    const isWhitelisted = TRUSTED_TOP_DOMAINS.has(url.domain);
    const hasNonStandardPort = url.port !== null && url.port !== 80 && url.port !== 443;

    return {
      url_length: url.canonical_url.length,
      host_length: url.host.length,
      path_length: url.path.length,
      query_length: url.query ? url.query.length : 0,
      subdomain_count: url.subdomains.length,
      path_depth: pathDepth,
      has_embedded_credentials: url.has_embedded_credentials,
      is_ip_literal: url.is_ip_literal,
      is_punycode: url.is_punycode,
      brand_token_detected: brandDetected,
      has_non_standard_port: hasNonStandardPort,
      phish_keyword_count: keywordCount,
      host_entropy: Math.round(hostEntropy * 1000) / 1000,
      scheme: url.scheme,
      host: url.host,
      unicode_host: url.unicode_host,
      port: url.port ?? (url.scheme === 'https' ? 443 : 80),
      domain: url.domain,
      is_whitelisted: isWhitelisted,
    };
  }

  public static calculateEntropy(str: string): number {
    if (!str) return 0.0;
    const len = str.length;
    const freq: Record<string, number> = {};
    for (let i = 0; i < len; i++) {
      const c = str[i];
      freq[c] = (freq[c] || 0) + 1;
    }

    let entropy = 0.0;
    for (const char of Object.keys(freq)) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}

