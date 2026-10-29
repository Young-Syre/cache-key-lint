/**
 * Cache-Control contradictions.
 *
 * These rules read only the response, so they are proofs about the directives
 * and nothing more. A directive contradiction is not a vulnerability on its
 * own; it is a statement that two caches in the path will behave differently,
 * which is the condition every finding in this tool needs.
 */

import { hasHeader, headerValue, parseVary } from '../headers.js';
import { describeIdentity, identitySignals } from '../identity.js';
import { directiveSeconds, parseDirectives, requestAuth, storability } from '../policy.js';
import type { Finding } from '../types.js';
import { ev, makeFinding, resourceLabel, type RuleContext } from './util.js';

export function directiveContradictions(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  for (const group of ctx.groups) {
    for (const entry of group.entries) {
      const ccRaw = headerValue(entry.response.headers, 'cache-control');
      const cc = parseDirectives(ccRaw);
      const cdnRaw =
        headerValue(entry.response.headers, 'cdn-cache-control') ??
        headerValue(entry.response.headers, 'surrogate-control');
      const cdn = parseDirectives(cdnRaw);
      const store = storability(entry.request, entry.response);
      const auth = requestAuth(entry.request);
      const authed = auth.authorizationHeader || auth.sessionCookies.length > 0;
      const resource = resourceLabel(entry);
      const maxAge = directiveSeconds(cc, 'max-age');
      const sMaxAge = directiveSeconds(cc, 's-maxage') ?? directiveSeconds(cdn, 's-maxage');
      const cdnMaxAge = directiveSeconds(cdn, 'max-age');

      // CKL-C001 — private with a positive max-age.
      if (cc.has('private') && maxAge !== null && maxAge > 0) {
        out.push(
          makeFinding('CKL-C001', {
            resource,
            summary: `Cache-Control declares private and max-age=${maxAge} together. The pair is legal but relies on every intermediary honouring private; one that reads only the freshness lifetime stores a response marked as belonging to a single user.`,
            kind: 'proof',
            evidence: [
              ev('Cache-Control', ccRaw ?? ''),
              ev('model verdict', store.reason),
              ev(
                'how to make it unambiguous',
                'use no-store for responses that must not be stored anywhere, or private with max-age=0 plus must-revalidate if browser caching is wanted',
              ),
            ],
            entries: [entry.index],
          }),
        );
      }

      // CKL-C002 — no-cache without no-store on an authenticated response.
      if (cc.has('no-cache') && !cc.has('no-store') && authed) {
        const signals = identitySignals(entry, group.entries, ctx.normalisers);
        out.push(
          makeFinding('CKL-C002', {
            resource,
            summary: `This response was produced for an authenticated request and carries no-cache without no-store. no-cache permits storing the body and only requires revalidation before reuse, so the authenticated content sits in the shared cache.`,
            kind: 'proof',
            evidence: [
              ev('Cache-Control', ccRaw ?? ''),
              ev(
                'authentication',
                auth.authorizationHeader
                  ? `the request carried Authorization: ${auth.scheme ?? 'credential'}`
                  : `the request carried the session cookie ${auth.sessionCookies.join(', ')}`,
              ),
              ev('what identified the user', describeIdentity(signals)),
              ev('model verdict', store.reason),
            ],
            entries: [entry.index],
          }),
        );
      }

      // CKL-C003 — s-maxage (or CDN-Cache-Control max-age) overriding a restrictive max-age.
      if (sMaxAge !== null && sMaxAge > 0 && maxAge !== null && maxAge <= 0) {
        out.push(
          makeFinding('CKL-C003', {
            resource,
            summary: `max-age=${maxAge} suggests the response must not be reused, but s-maxage=${sMaxAge} applies to shared caches and takes precedence there. Browsers revalidate; the CDN keeps the response for ${sMaxAge} seconds.`,
            kind: 'proof',
            evidence: [
              ev('Cache-Control', ccRaw ?? ''),
              ...(cdnRaw === null ? [] : [ev('CDN directive', cdnRaw)]),
              ev('model verdict', store.reason),
            ],
            entries: [entry.index],
          }),
        );
      } else if (cdnMaxAge !== null && cdnMaxAge > 0 && maxAge !== null && maxAge <= 0) {
        out.push(
          makeFinding('CKL-C003', {
            resource,
            summary: `max-age=${maxAge} applies to private caches, while the CDN-targeted directive sets max-age=${cdnMaxAge}. The two audiences get different answers, and the shared one is the permissive answer.`,
            kind: 'proof',
            evidence: [
              ev('Cache-Control', ccRaw ?? ''),
              ev('CDN directive', cdnRaw ?? ''),
              ev('model verdict', store.reason),
            ],
            entries: [entry.index],
          }),
        );
      }

      // CKL-C004 — revalidation asked for, but not required.
      if (
        (cc.has('no-cache') || maxAge === 0 || sMaxAge === 0) &&
        !cc.has('must-revalidate') &&
        !cc.has('proxy-revalidate') &&
        !cc.has('no-store')
      ) {
        out.push(
          makeFinding('CKL-C004', {
            resource,
            summary: `The response asks caches to revalidate (${cc.has('no-cache') ? 'no-cache' : 'max-age=0'}) but does not carry must-revalidate or proxy-revalidate, so a cache is permitted to serve the stored copy when the origin cannot be reached.`,
            kind: 'proof',
            evidence: [
              ev('Cache-Control', ccRaw ?? ''),
              ev(
                'why it matters',
                'the moment the origin is unreachable is also the moment stale authenticated content is most likely to be served to the wrong person',
              ),
              ev('model verdict', store.reason),
            ],
            entries: [entry.index],
          }),
        );
      }

      // CKL-C005 — stale-while-revalidate / stale-if-error.
      const swr = directiveSeconds(cc, 'stale-while-revalidate') ?? directiveSeconds(cdn, 'stale-while-revalidate');
      const sie = directiveSeconds(cc, 'stale-if-error') ?? directiveSeconds(cdn, 'stale-if-error');
      if ((swr !== null && swr > 0) || (sie !== null && sie > 0)) {
        const parts: string[] = [];
        if (swr !== null) parts.push(`stale-while-revalidate=${swr}`);
        if (sie !== null) parts.push(`stale-if-error=${sie}`);
        const total = (maxAge ?? sMaxAge ?? 0) + Math.max(swr ?? 0, sie ?? 0);
        out.push(
          makeFinding('CKL-C005', {
            resource,
            summary: `${parts.join(' and ')} allow a cache to serve this response after it has expired, so the window in which a stored copy can be handed out is about ${total} seconds rather than ${maxAge ?? sMaxAge ?? 0}.`,
            kind: 'proof',
            evidence: [
              ev('Cache-Control', ccRaw ?? ''),
              ...(cdnRaw === null ? [] : [ev('CDN directive', cdnRaw)]),
              ev('exposure window', `freshness ${maxAge ?? sMaxAge ?? 0}s + stale window ${Math.max(swr ?? 0, sie ?? 0)}s`),
              ev('model verdict', store.reason),
            ],
            entries: [entry.index],
          }),
        );
      }

      // CKL-C006 — Pragma on its own.
      if (hasHeader(entry.response.headers, 'pragma') && ccRaw === null) {
        out.push(
          makeFinding('CKL-C006', {
            resource,
            summary: `The response carries Pragma: ${headerValue(entry.response.headers, 'pragma') ?? ''} and no Cache-Control. Pragma is defined as a request header for HTTP/1.0 compatibility; as a response header it has no required effect, so this response has no cache controls at all.`,
            kind: 'proof',
            evidence: [
              ev('Pragma', headerValue(entry.response.headers, 'pragma') ?? ''),
              ev('Cache-Control', 'absent'),
              ev('model verdict', store.reason),
            ],
            entries: [entry.index],
          }),
        );
      }

      // CKL-C007 — nothing at all.
      if (ccRaw === null && cdnRaw === null && store.heuristic) {
        const signals = identitySignals(entry, group.entries, ctx.normalisers);
        out.push(
          makeFinding('CKL-C007', {
            resource,
            summary: `The response carries no Cache-Control and no Expires, and status ${entry.response.status} is heuristically cacheable, so a shared cache may invent a freshness lifetime for it. ${
              signals.length > 0 ? 'The response also identifies a user.' : ''
            }`.trim(),
            kind: 'proof',
            severity: signals.length > 0 ? 'high' : 'medium',
            evidence: [
              ev('headers', `no Cache-Control, no Expires, status ${entry.response.status}`),
              ev('Vary', parseVary(entry.response.headers).join(', ') || 'absent'),
              ...(signals.length > 0 ? [ev('what identified the user', describeIdentity(signals))] : []),
              ev('model verdict', store.reason),
            ],
            entries: [entry.index],
          }),
        );
      }
    }
  }
  return out;
}

export const DIRECTIVE_RULES = [directiveContradictions] as const;
