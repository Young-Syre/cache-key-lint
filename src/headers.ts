import type { HeaderPair } from './types.js';

export function makeHeader(name: string, value: string): HeaderPair {
  return { name, lower: name.toLowerCase(), value };
}

export function headerValue(headers: readonly HeaderPair[], name: string): string | null {
  const want = name.toLowerCase();
  for (const h of headers) if (h.lower === want) return h.value;
  return null;
}

export function headerValues(headers: readonly HeaderPair[], name: string): string[] {
  const want = name.toLowerCase();
  return headers.filter((h) => h.lower === want).map((h) => h.value);
}

export function hasHeader(headers: readonly HeaderPair[], name: string): boolean {
  return headerValue(headers, name) !== null;
}

export function headerNames(headers: readonly HeaderPair[]): string[] {
  return [...new Set(headers.map((h) => h.lower))].sort();
}

/**
 * Collapse repeated headers into one value per name, joined with ", " — the
 * list-header rule from RFC 9110 section 5.3. Two captures that record the
 * same list header split differently must not look like a difference.
 */
export function foldHeaders(headers: readonly HeaderPair[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const h of headers) {
    const prev = out.get(h.lower);
    out.set(h.lower, prev === undefined ? h.value : `${prev}, ${h.value}`);
  }
  return out;
}

/** Parse a `Vary` header into lowercase tokens. `*` is preserved verbatim. */
export function parseVary(headers: readonly HeaderPair[]): string[] {
  const raw = headerValues(headers, 'vary').join(',');
  if (raw.trim() === '') return [];
  return [
    ...new Set(
      raw
        .split(',')
        .map((t) => t.trim().toLowerCase())
        .filter((t) => t !== ''),
    ),
  ];
}

/** Lowercase cookie name -> value, from a request `Cookie` header. */
export function parseCookieHeader(headers: readonly HeaderPair[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of headerValues(headers, 'cookie')) {
    for (const part of raw.split(';')) {
      const eq = part.indexOf('=');
      if (eq <= 0) continue;
      const name = part.slice(0, eq).trim();
      if (name === '') continue;
      out.set(name.toLowerCase(), part.slice(eq + 1).trim());
    }
  }
  return out;
}

/** Cookie names set by a response, lowercased. */
export function setCookieNames(headers: readonly HeaderPair[]): string[] {
  const out: string[] = [];
  for (const raw of headerValues(headers, 'set-cookie')) {
    const eq = raw.indexOf('=');
    if (eq > 0) out.push(raw.slice(0, eq).trim().toLowerCase());
  }
  return [...new Set(out)];
}

/**
 * Routing headers a reverse proxy or framework may read to build absolute
 * URLs, and which a CDN very rarely includes in its cache key. This list is
 * the poisoning surface: each one is an input that reaches the origin,
 * influences the response, and is invisible to the key.
 */
export const ROUTING_HEADERS: readonly { name: string; why: string }[] = [
  { name: 'X-Forwarded-Host', why: 'de-facto standard for the client-facing host; many frameworks build absolute URLs from it' },
  { name: 'X-Forwarded-Scheme', why: 'scheme half of the same pattern; flips http/https in generated URLs' },
  { name: 'X-Forwarded-Proto', why: 'the standardised spelling of the scheme hint; can force a redirect loop or downgrade' },
  { name: 'X-Forwarded-Port', why: 'appended to the host in some URL builders, giving a partial injection' },
  { name: 'X-Forwarded-Prefix', why: 'path prefix hint; relocates generated links and asset paths' },
  { name: 'X-Forwarded-Server', why: 'host variant honoured by some proxy configurations' },
  { name: 'X-Host', why: 'host variant honoured by some proxies and CDNs' },
  { name: 'X-Original-URL', why: 'overrides the request path after the cache has keyed on the original path' },
  { name: 'X-Rewrite-URL', why: 'same as X-Original-URL in other stacks' },
  { name: 'X-Original-Host', why: 'host variant' },
  { name: 'X-Real-IP', why: 'drives geo/locale branching, and sometimes access decisions' },
  { name: 'Forwarded', why: 'the RFC 7239 header that supersedes the X-Forwarded-* family' },
  { name: 'X-HTTP-Method-Override', why: 'changes the effective method behind a GET-keyed cache entry' },
  { name: 'Accept-Language', why: 'commonly drives locale branching while being absent from Vary' },
];

/** Headers whose values are credentials and are redacted by default. */
export const CREDENTIAL_HEADERS: readonly string[] = [
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'authentication',
  'x-api-key',
  'api-key',
  'apikey',
  'x-auth-token',
  'x-access-token',
  'x-session-token',
  'x-csrf-token',
  'x-xsrf-token',
  'x-amz-security-token',
  'x-goog-iam-authorization-token',
];

/**
 * Cache-status headers emitted by CDNs and reverse proxies. These are treated
 * purely as capture evidence — the tool reports what the header said, it does
 * not model any vendor's key algorithm.
 */
export const CACHE_STATUS_HEADERS: readonly { name: string; vendor: string; hit: readonly string[] }[] = [
  { name: 'CF-Cache-Status', vendor: 'Cloudflare', hit: ['hit', 'stale', 'updating', 'revalidated'] },
  { name: 'X-Cache', vendor: 'Varnish, CloudFront, Fastly and others', hit: ['hit'] },
  { name: 'X-Cache-Hits', vendor: 'Varnish / Fastly (hit counter)', hit: [] },
  { name: 'X-Vercel-Cache', vendor: 'Vercel', hit: ['hit', 'stale'] },
  { name: 'X-Served-By', vendor: 'Fastly (serving node)', hit: [] },
  { name: 'Fastly-Debug-Digest', vendor: 'Fastly (hashed key material)', hit: [] },
  { name: 'X-Drupal-Cache', vendor: 'Drupal page cache', hit: ['hit'] },
  { name: 'X-Proxy-Cache', vendor: 'nginx proxy_cache', hit: ['hit'] },
  { name: 'CDN-Cache-Control', vendor: 'CDN-targeted directive (RFC 9213)', hit: [] },
  { name: 'Surrogate-Control', vendor: 'Fastly / Squid surrogate directive', hit: [] },
  { name: 'Surrogate-Key', vendor: 'Fastly purge tagging', hit: [] },
  { name: 'Age', vendor: 'any RFC 9111 shared cache', hit: [] },
];

export const CACHE_STATUS_LOWER: readonly string[] = CACHE_STATUS_HEADERS.map((h) =>
  h.name.toLowerCase(),
);

/** True when a cache-status header's value indicates the response was served from store. */
export function isHitValue(headerLower: string, value: string): boolean {
  const v = value.trim().toLowerCase();
  const meta = CACHE_STATUS_HEADERS.find((h) => h.name.toLowerCase() === headerLower);
  if (meta === undefined) return false;
  if (headerLower === 'age') {
    const n = Number.parseInt(v, 10);
    return Number.isFinite(n) && n > 0;
  }
  if (headerLower === 'x-cache-hits') {
    const n = Number.parseInt(v, 10);
    return Number.isFinite(n) && n > 0;
  }
  // `X-Cache: HIT from node-1` and `cf-cache-status: HIT` both match on token.
  const tokens = v.split(/[\s,;/]+/).filter((t) => t !== '');
  return meta.hit.some((h) => tokens.includes(h));
}

export function cacheVendor(headerLower: string): string {
  const meta = CACHE_STATUS_HEADERS.find((h) => h.name.toLowerCase() === headerLower);
  return meta === undefined ? 'unknown' : meta.vendor;
}
