/**
 * Cache-Control modelling and storability.
 *
 * Deliberately a simplified reading of RFC 9111 sections 3 and 5.2, kept
 * explicit so that every verdict can be explained in one line of report
 * output. It models what a *conformant* shared cache is permitted to do. Real
 * CDNs are more permissive than the RFC in places and more conservative in
 * others; where the capture contains a vendor cache-status header, that
 * observation is reported alongside and always outranks this model.
 */

import { headerValue, headerValues, hasHeader, parseCookieHeader } from './headers.js';
import type { CapturedRequest, CapturedResponse } from './types.js';

export type Directives = Map<string, string | null>;

export function parseDirectives(raw: string | null): Directives {
  const out: Directives = new Map();
  if (raw === null) return out;
  for (const part of raw.split(',')) {
    const t = part.trim();
    if (t === '') continue;
    const eq = t.indexOf('=');
    if (eq === -1) {
      out.set(t.toLowerCase(), null);
      continue;
    }
    const name = t.slice(0, eq).trim().toLowerCase();
    let value = t.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
    out.set(name, value);
  }
  return out;
}

export function directiveSeconds(d: Directives, name: string): number | null {
  if (!d.has(name)) return null;
  const v = d.get(name);
  if (v === null || v === undefined || v === '') return null;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : null;
}

/** Statuses a cache may store without explicit freshness information (RFC 9111 §4.2.2). */
export const HEURISTICALLY_CACHEABLE_STATUSES: readonly number[] = [
  200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501,
];

const SESSION_COOKIE_RE = /sess|sid$|^sid|token|auth|jwt|login|remember|identity|csrf_?user/i;

export interface RequestAuth {
  /** The request carried an Authorization or Proxy-Authorization header. */
  readonly authorizationHeader: boolean;
  readonly scheme: string | null;
  /** Names of request cookies whose names look session-bearing. */
  readonly sessionCookies: readonly string[];
  readonly anyCookies: readonly string[];
}

export function requestAuth(request: CapturedRequest): RequestAuth {
  const auth = headerValue(request.headers, 'authorization') ?? headerValue(request.headers, 'proxy-authorization');
  const cookies = [...parseCookieHeader(request.headers).keys()];
  const scheme = auth === null ? null : (auth.split(/\s+/)[0] ?? null);
  return {
    authorizationHeader: auth !== null,
    scheme,
    sessionCookies: cookies.filter((c) => SESSION_COOKIE_RE.test(c)),
    anyCookies: cookies,
  };
}

export interface Storability {
  /** A conformant shared cache is permitted to store the response. */
  readonly mayStore: boolean;
  /** It may store it, but must revalidate before every reuse. */
  readonly requiresRevalidation: boolean;
  /** Storage rests on heuristic freshness rather than an explicit directive. */
  readonly heuristic: boolean;
  /** One-line explanation naming the directive or rule that decided it. */
  readonly reason: string;
  readonly directives: Directives;
  /** CDN-Cache-Control / Surrogate-Control, which take precedence at the CDN. */
  readonly cdnDirectives: Directives;
}

/**
 * Whether a shared cache may store this response.
 *
 * The Authorization clause is the one that produces most real findings:
 * RFC 9111 §3.5 forbids a shared cache from storing a response to a request
 * with an Authorization header *unless* the response carries public,
 * must-revalidate or s-maxage — so adding `public` to an authenticated
 * endpoint switches storage on rather than merely permitting it.
 */
export function storability(request: CapturedRequest, response: CapturedResponse): Storability {
  const cc = parseDirectives(headerValue(response.headers, 'cache-control'));
  const cdn = parseDirectives(
    headerValue(response.headers, 'cdn-cache-control') ?? headerValue(response.headers, 'surrogate-control'),
  );
  const effective: Directives = new Map([...cc, ...cdn]);
  const auth = requestAuth(request);
  const sMaxAge = directiveSeconds(effective, 's-maxage');
  const maxAge = directiveSeconds(effective, 'max-age');
  const base = { directives: cc, cdnDirectives: cdn };

  if (effective.has('no-store')) {
    return { mayStore: false, requiresRevalidation: false, heuristic: false, reason: 'no-store forbids storage', ...base };
  }
  if (!['GET', 'HEAD'].includes(request.method)) {
    return {
      mayStore: false,
      requiresRevalidation: false,
      heuristic: false,
      reason: `method ${request.method} is not cacheable by default`,
      ...base,
    };
  }
  if (effective.has('private')) {
    if (sMaxAge !== null && sMaxAge > 0) {
      return {
        mayStore: true,
        requiresRevalidation: false,
        heuristic: false,
        reason: `private is overridden for shared caches by s-maxage=${sMaxAge}`,
        ...base,
      };
    }
    return { mayStore: false, requiresRevalidation: false, heuristic: false, reason: 'private excludes shared caches', ...base };
  }
  if (auth.authorizationHeader) {
    if (effective.has('public')) {
      return {
        mayStore: true,
        requiresRevalidation: effective.has('no-cache'),
        heuristic: false,
        reason: 'request was Authorization-gated and the response is marked public (RFC 9111 §3.5)',
        ...base,
      };
    }
    if (sMaxAge !== null) {
      return {
        mayStore: true,
        requiresRevalidation: effective.has('no-cache'),
        heuristic: false,
        reason: `request was Authorization-gated and s-maxage=${sMaxAge} permits shared storage (RFC 9111 §3.5)`,
        ...base,
      };
    }
    if (effective.has('must-revalidate')) {
      return {
        mayStore: true,
        requiresRevalidation: true,
        heuristic: false,
        reason: 'request was Authorization-gated and must-revalidate permits shared storage (RFC 9111 §3.5)',
        ...base,
      };
    }
    return {
      mayStore: false,
      requiresRevalidation: false,
      heuristic: false,
      reason: 'Authorization-gated request without public, s-maxage or must-revalidate',
      ...base,
    };
  }
  if (effective.has('no-cache')) {
    return {
      mayStore: true,
      requiresRevalidation: true,
      heuristic: false,
      reason: 'no-cache permits storage and requires revalidation before reuse',
      ...base,
    };
  }
  if (effective.has('public')) {
    return { mayStore: true, requiresRevalidation: false, heuristic: false, reason: 'public permits shared storage', ...base };
  }
  if (sMaxAge !== null && sMaxAge > 0) {
    return { mayStore: true, requiresRevalidation: false, heuristic: false, reason: `s-maxage=${sMaxAge}`, ...base };
  }
  if (maxAge !== null && maxAge > 0) {
    return { mayStore: true, requiresRevalidation: false, heuristic: false, reason: `max-age=${maxAge}`, ...base };
  }
  if (maxAge === 0 || sMaxAge === 0) {
    return {
      mayStore: true,
      requiresRevalidation: true,
      heuristic: false,
      reason: 'max-age=0 permits storage but no reuse without revalidation',
      ...base,
    };
  }
  if (cc.size === 0 && cdn.size === 0) {
    if (hasHeader(response.headers, 'expires')) {
      return {
        mayStore: true,
        requiresRevalidation: false,
        heuristic: false,
        reason: 'no Cache-Control; freshness comes from Expires',
        ...base,
      };
    }
    if (HEURISTICALLY_CACHEABLE_STATUSES.includes(response.status)) {
      return {
        mayStore: true,
        requiresRevalidation: false,
        heuristic: true,
        reason: `no Cache-Control and status ${response.status} is heuristically cacheable (RFC 9111 §4.2.2)`,
        ...base,
      };
    }
  }
  return {
    mayStore: false,
    requiresRevalidation: false,
    heuristic: false,
    reason: 'no directive permits shared storage',
    ...base,
  };
}

/** The `Age` value as an integer, or null when absent or unparseable. */
export function ageSeconds(response: CapturedResponse): number | null {
  const raw = headerValues(response.headers, 'age')[0];
  if (raw === undefined) return null;
  const n = Number.parseInt(raw.trim(), 10);
  return Number.isFinite(n) ? n : null;
}
