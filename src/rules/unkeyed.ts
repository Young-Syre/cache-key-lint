/**
 * Unkeyed input — the cache-poisoning half.
 *
 * Every rule here answers one question: is there something in the request that
 * changes the response and is not in the key? The capture can show the first
 * half directly. The second half is almost never observable from outside, so
 * these rules are mostly inferences and say so.
 */

import { ROUTING_HEADERS, foldHeaders, headerValue, parseVary } from '../headers.js';
import { anyHit, pairs, requestDelta, responseDelta } from '../group.js';
import { storability } from '../policy.js';
import type { CaptureEntry, Finding } from '../types.js';
import { parseUrl } from '../url.js';
import { ev, makeFinding, resourceLabel, type RuleContext } from './util.js';

const ROUTING_LOWER = new Map(ROUTING_HEADERS.map((h) => [h.name.toLowerCase(), h]));

/** CKL-U001 — the core finding: a response that varies with a header not in Vary. */
export function unkeyedHeader(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const group of ctx.groups) {
    for (const [a, b] of pairs(group.entries)) {
      const delta = requestDelta(a, b);
      if (delta.dimensions !== 1 || delta.headers.length !== 1) continue;
      const header = delta.headers[0] as string;
      const rdelta = responseDelta(a, b, ctx.normalisers);
      if (!rdelta.varied) continue;
      const varyA = parseVary(a.response.headers);
      const varyB = parseVary(b.response.headers);
      const inVary = varyA.includes(header) || varyB.includes(header);
      if (inVary) continue;
      const dedupe = `${group.key}|${header}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);

      const hitA = anyHit(a);
      const hitB = anyHit(b);
      const hit = hitA ?? hitB;
      const kind = hit === null ? ('inference' as const) : ('proof' as const);
      const foldedA = foldHeaders(a.request.headers);
      const foldedB = foldHeaders(b.request.headers);
      const what: string[] = [];
      if (rdelta.statusDiffers) what.push(`status ${a.response.status} vs ${b.response.status}`);
      if (rdelta.bodyDiffers) what.push('the normalised body');
      if (rdelta.headers.length > 0) what.push(`the response header(s) ${rdelta.headers.join(', ')}`);

      out.push(
        makeFinding('CKL-U001', {
          resource: `${a.request.method} ${group.key}`,
          summary: `The response varies with the request header ${header}, and no Vary header names it. ${what.join(' and ')} changed when only that header changed.`,
          kind,
          confidence: hit === null ? 0.7 : 1,
          evidence: [
            ev(
              'single-variable pair',
              `entries ${a.index} and ${b.index} differ in exactly one request component: ${header} = ${ctx.redactor.text(String(foldedA.get(header) ?? '(absent)'))} vs ${ctx.redactor.text(String(foldedB.get(header) ?? '(absent)'))}`,
            ),
            ev('response changed', what.join('; ')),
            ev(
              'Vary',
              varyA.length === 0 && varyB.length === 0
                ? 'neither response carried a Vary header'
                : `Vary was ${[...new Set([...varyA, ...varyB])].join(', ')}, which does not include ${header}`,
            ),
            ...(hit === null
              ? [
                  ev(
                    'why this is an inference',
                    'the capture shows the response varying with the header; it does not show the cache key, so whether the header is actually unkeyed has to be confirmed with the request matrix from `plan`',
                  ),
                ]
              : [
                  ev(
                    'cache evidence',
                    `${hit.header.name}: ${hit.header.value} on entry ${hitA === null ? b.index : a.index} shows a shared cache (${hit.vendor}) served a stored response for this resource`,
                  ),
                ]),
          ],
          entries: [a.index, b.index],
        }),
      );
    }
  }
  return out;
}

interface Landing {
  readonly where: string;
  readonly excerpt: string;
}

/** Where in the response an injected value came back out. */
function findLandings(entry: CaptureEntry, value: string): Landing[] {
  const out: Landing[] = [];
  const body = entry.response.body ?? '';
  const location = headerValue(entry.response.headers, 'location');
  if (location !== null && location.includes(value)) {
    out.push({ where: 'the Location header', excerpt: location });
  }
  const contentLocation = headerValue(entry.response.headers, 'content-location');
  if (contentLocation !== null && contentLocation.includes(value)) {
    out.push({ where: 'the Content-Location header', excerpt: contentLocation });
  }
  const link = headerValue(entry.response.headers, 'link');
  if (link !== null && link.includes(value)) out.push({ where: 'the Link header', excerpt: link });

  const patterns: { where: string; re: RegExp }[] = [
    { where: 'a <script src>', re: new RegExp(`<script[^>]{0,200}src\\s*=\\s*["'][^"']*${escapeRe(value)}[^"']*["']`, 'i') },
    { where: 'a <link href>', re: new RegExp(`<link[^>]{0,200}href\\s*=\\s*["'][^"']*${escapeRe(value)}[^"']*["']`, 'i') },
    { where: 'a canonical link', re: new RegExp(`<link[^>]{0,200}rel\\s*=\\s*["']canonical["'][^>]{0,200}${escapeRe(value)}`, 'i') },
    { where: 'an og: meta tag', re: new RegExp(`<meta[^>]{0,200}(?:property|name)\\s*=\\s*["']og:[^"']*["'][^>]{0,200}${escapeRe(value)}`, 'i') },
    { where: 'a <form action>', re: new RegExp(`<form[^>]{0,200}action\\s*=\\s*["'][^"']*${escapeRe(value)}`, 'i') },
    { where: 'an <img src>', re: new RegExp(`<img[^>]{0,200}src\\s*=\\s*["'][^"']*${escapeRe(value)}`, 'i') },
    { where: 'an absolute URL in the body', re: new RegExp(`(?:https?:)?//${escapeRe(value)}`, 'i') },
    { where: 'a JSON string field', re: new RegExp(`"[^"\\n]{0,80}${escapeRe(value)}[^"\\n]{0,80}"`) },
  ];
  const matched: Landing[] = [];
  for (const p of patterns) {
    const m = p.re.exec(body);
    if (m !== null) matched.push({ where: p.where, excerpt: m[0].slice(0, 200) });
  }
  // Keep the most specific landing per sink: a canonical link also matches the
  // generic <link href> and absolute-URL patterns, and listing all three says
  // nothing extra.
  const specific = matched.filter(
    (l) => l.where !== 'an absolute URL in the body' && l.where !== 'a JSON string field',
  );
  const kept = (specific.length > 0 ? specific : matched).filter(
    (l) => !(l.where === 'a <link href>' && specific.some((o) => o.where === 'a canonical link')),
  );
  out.push(...kept);
  if (out.length === 0 && body.includes(value)) {
    const at = body.indexOf(value);
    out.push({ where: 'the response body', excerpt: body.slice(Math.max(0, at - 40), at + value.length + 40) });
  }
  return out;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** CKL-U002 — a routing header whose value came back out in the response. */
export function reflectedRoutingHeader(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  for (const entry of ctx.entries) {
    for (const header of entry.request.headers) {
      const meta = ROUTING_LOWER.get(header.lower);
      if (meta === undefined) continue;
      const value = header.value.trim();
      if (value.length < 4) continue;
      // `Forwarded: host=x;proto=https` — look for the host token, not the whole header.
      const needles = header.lower === 'forwarded'
        ? [...value.matchAll(/host=([^;,\s]+)/gi)].map((m) => m[1] ?? '').filter((v) => v.length >= 4)
        : [value];
      for (const needle of needles) {
        const landings = findLandings(entry, needle);
        if (landings.length === 0) continue;
        const store = storability(entry.request, entry.response);
        const hit = anyHit(entry);
        out.push(
          makeFinding('CKL-U002', {
            resource: resourceLabel(entry),
            summary: `The value of ${header.name} is reflected into the response at ${landings.map((l) => l.where).join(', ')}. ${
              store.mayStore
                ? `A shared cache may store this response (${store.reason}), so one request fixes that value for every later client.`
                : `The response is not storable by a shared cache as captured (${store.reason}), so this is a reflection without a cache sink unless the directives change.`
            }`,
            kind: 'proof',
            severity: store.mayStore ? 'high' : 'medium',
            evidence: [
              ev('header sent', `${header.name}: ${ctx.redactor.text(header.value)} (${meta.why})`),
              ...landings.map((l) => ev(`landed in ${l.where}`, ctx.redactor.text(l.excerpt))),
              ev('storability', store.reason),
              ev(
                'attacker control',
                hit === null
                  ? 'the value was supplied by the client in this capture and reached the response, which proves the origin reads it; whether an internet client can reach the origin with the same header depends on the network path and is not observable from the capture'
                  : `${hit.header.name}: ${hit.header.value} shows the request traversed a shared cache (${hit.vendor}), so the same path is reachable from the client side`,
              ),
            ],
            entries: [entry.index],
          }),
        );
      }
    }
  }
  return out;
}

/** CKL-U003 — the response varies with a query parameter. */
export function unkeyedQueryParameter(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const group of ctx.groups) {
    for (const [a, b] of pairs(group.entries)) {
      const delta = requestDelta(a, b);
      if (delta.dimensions !== 1 || delta.queryValues.length !== 1) continue;
      const diff = delta.queryValues[0] as { name: string; a: string | null; b: string | null };
      const rdelta = responseDelta(a, b, ctx.normalisers);
      if (!rdelta.varied) continue;
      const dedupe = `${group.key}|${diff.name}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      const hit = anyHit(a) ?? anyHit(b);
      out.push(
        makeFinding('CKL-U003', {
          resource: `${a.request.method} ${group.key}`,
          summary: `The response varies with the query parameter ${diff.name}. If the cache's key excludes it — the common configuration for tracking and locale parameters — one value of ${diff.name} is served for all of them.`,
          kind: 'inference',
          confidence: hit === null ? 0.5 : 0.75,
          evidence: [
            ev(
              'single-variable pair',
              `entries ${a.index} and ${b.index} differ only in ${diff.name}: ${diff.a ?? '(absent)'} vs ${diff.b ?? '(absent)'}`,
            ),
            ev(
              'response changed',
              [
                rdelta.statusDiffers ? `status ${a.response.status} vs ${b.response.status}` : '',
                rdelta.bodyDiffers ? 'the normalised body' : '',
                rdelta.headers.length > 0 ? `response header(s) ${rdelta.headers.join(', ')}` : '',
              ]
                .filter((s) => s !== '')
                .join('; '),
            ),
            ev(
              'why this is an inference',
              'the capture shows the origin branching on the parameter. Whether the cache keys on it is a configuration the capture cannot reveal — confirm with the parameter matrix from `plan`',
            ),
            ...(hit === null
              ? []
              : [ev('cache evidence', `${hit.header.name}: ${hit.header.value} (${hit.vendor}) on one of the two entries`)]),
          ],
          entries: [a.index, b.index],
        }),
      );
    }
  }
  return out;
}

/** CKL-U004 — two spellings of the same query, treated differently. */
export function queryNormalisationDisagreement(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  for (const group of ctx.groups) {
    for (const [a, b] of pairs(group.entries)) {
      const delta = requestDelta(a, b);
      if (delta.querySpelling.length === 0) continue;
      if (delta.dimensions !== 1) continue;
      const rdelta = responseDelta(a, b, ctx.normalisers);
      const hit = anyHit(a) ?? anyHit(b);
      const classes = delta.querySpelling.join(', ');
      if (rdelta.varied) {
        out.push(
          makeFinding('CKL-U004', {
            resource: `${a.request.method} ${group.key}`,
            summary: `Two spellings of the same query (${classes}) produced different responses, so the origin distinguishes them. A cache that canonicalises the query would serve one for the other; a cache that does not splits the key.`,
            kind: hit === null ? 'inference' : 'proof',
            confidence: hit === null ? 0.6 : 1,
            evidence: [
              ev('spelling classes', classes),
              ev('queries', `entry ${a.index}: ?${parseUrl(a.request.url).search || '(none)'} — entry ${b.index}: ?${parseUrl(b.request.url).search || '(none)'}`),
              ev('origin distinguishes them', rdelta.bodyDiffers ? 'the normalised bodies differ' : `response header(s) ${rdelta.headers.join(', ')} differ`),
              ...(hit === null
                ? [ev('why this is an inference', 'the direction of the disagreement depends on the cache’s canonicalisation, which is not in the capture')]
                : [ev('cache evidence', `${hit.header.name}: ${hit.header.value} (${hit.vendor})`)]),
            ],
            entries: [a.index, b.index],
          }),
        );
        continue;
      }
      if (hit !== null) {
        out.push(
          makeFinding('CKL-U004', {
            resource: `${a.request.method} ${group.key}`,
            summary: `Two spellings of the same query (${classes}) returned the same response and a cache hit, so the two spellings share one key. Each extra spelling is an extra key an attacker can choose and a victim can be steered to.`,
            kind: 'proof',
            severity: 'low',
            evidence: [
              ev('spelling classes', classes),
              ev('queries', `entry ${a.index}: ?${parseUrl(a.request.url).search || '(none)'} — entry ${b.index}: ?${parseUrl(b.request.url).search || '(none)'}`),
              ev('cache evidence', `${hit.header.name}: ${hit.header.value} (${hit.vendor})`),
            ],
            entries: [a.index, b.index],
          }),
        );
      }
    }
  }
  return out;
}

/** CKL-U005 — the response varies with a cookie and Vary: Cookie is absent. */
export function unkeyedCookie(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const group of ctx.groups) {
    for (const [a, b] of pairs(group.entries)) {
      const delta = requestDelta(a, b);
      if (delta.dimensions !== 1 || delta.cookies.length === 0) continue;
      const rdelta = responseDelta(a, b, ctx.normalisers);
      if (!rdelta.varied) continue;
      const vary = [...parseVary(a.response.headers), ...parseVary(b.response.headers)];
      if (vary.includes('cookie')) continue;
      const names = delta.cookies.join(', ');
      const dedupe = `${group.key}|${names}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      const store = storability(a.request, a.response);
      const hit = anyHit(a) ?? anyHit(b);
      out.push(
        makeFinding('CKL-U005', {
          resource: `${a.request.method} ${group.key}`,
          summary: `The response varies with the cookie ${names} and no response declares Vary: Cookie. ${
            store.mayStore
              ? `A shared cache may store it (${store.reason}), so one user's response is the response every user gets.`
              : `As captured the response is not storable by a shared cache (${store.reason}), so this is a latent problem rather than an active one.`
          }`,
          kind: hit === null ? 'inference' : 'proof',
          confidence: hit === null ? 0.75 : 1,
          severity: store.mayStore ? 'high' : 'medium',
          evidence: [
            ev('single-variable pair', `entries ${a.index} and ${b.index} differ only in the cookie ${names} (values redacted)`),
            ev('response changed', rdelta.bodyDiffers ? 'the normalised bodies differ' : `response header(s) ${rdelta.headers.join(', ')} differ`),
            ev('Vary', vary.length === 0 ? 'no Vary header was present' : `Vary was ${[...new Set(vary)].join(', ')}`),
            ev('storability', store.reason),
            ...(hit === null
              ? [
                  ev(
                    'why this is an inference',
                    'the capture shows the origin branching on the cookie; whether the cache includes cookies in its key is a configuration the capture cannot reveal, so confirm with the cookie probe from `plan`',
                  ),
                ]
              : [ev('cache evidence', `${hit.header.name}: ${hit.header.value} (${hit.vendor})`)]),
          ],
          entries: [a.index, b.index],
        }),
      );
    }
  }
  return out;
}

/** CKL-U006, CKL-U007, CKL-U008 — Vary present but not useful. */
export function varyProblems(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const reportedStar = new Set<string>();
  const reportedUa = new Set<string>();
  for (const group of ctx.groups) {
    for (const entry of group.entries) {
      const vary = parseVary(entry.response.headers);
      if (vary.length === 0) continue;
      const store = storability(entry.request, entry.response);
      if (vary.includes('*') && !reportedStar.has(group.key)) {
        reportedStar.add(group.key);
        out.push(
          makeFinding('CKL-U006', {
            resource: resourceLabel(entry),
            summary:
              'Vary: * means no stored response can ever be selected, so either this resource is never served from cache or something in the path is ignoring the header. Both readings matter and the response alone cannot distinguish them.',
            kind: 'proof',
            evidence: [
              ev('Vary', `Vary: ${vary.join(', ')}`),
              ev('storability', store.reason),
              ev(
                'what to do with it',
                'treat it as a statement of intent, not a control: confirm with a cache-buster pair whether the resource is ever served from a shared cache',
              ),
            ],
            entries: [entry.index],
          }),
        );
      }
      if (vary.includes('user-agent') && !reportedUa.has(group.key)) {
        reportedUa.add(group.key);
        out.push(
          makeFinding('CKL-U008', {
            resource: resourceLabel(entry),
            summary:
              'Vary: User-Agent is being used to separate responses. User-Agent has unbounded cardinality, so caches normalise it into coarse buckets or drop it, and two clients the origin considers different can share one key.',
            kind: 'proof',
            evidence: [ev('Vary', `Vary: ${vary.join(', ')}`), ev('storability', store.reason)],
            entries: [entry.index],
          }),
        );
      }
    }

    // A Vary token the origin demonstrably does not read.
    const varyTokens = new Set<string>();
    for (const e of group.entries) for (const t of parseVary(e.response.headers)) varyTokens.add(t);
    for (const token of varyTokens) {
      if (token === '*' || token === 'accept-encoding') continue;
      for (const [a, b] of pairs(group.entries)) {
        const delta = requestDelta(a, b);
        if (delta.dimensions !== 1 || delta.headers.length !== 1 || delta.headers[0] !== token) continue;
        const rdelta = responseDelta(a, b, ctx.normalisers);
        if (rdelta.varied) continue;
        out.push(
          makeFinding('CKL-U007', {
            resource: `${a.request.method} ${group.key}`,
            summary: `Vary names ${token}, but changing ${token} did not change the response. The listed header fragments the cache without separating anything, and its presence makes the Vary list look more considered than it is.`,
            kind: 'inference',
            confidence: 0.7,
            evidence: [
              ev('Vary', `Vary includes ${token}`),
              ev('single-variable pair', `entries ${a.index} and ${b.index} differ only in ${token} and returned equivalent responses`),
              ev(
                'why this is an inference',
                'two observations are not proof that the origin never reads the header; a third value, or a different code path, may well read it',
              ),
            ],
            entries: [a.index, b.index],
          }),
        );
        break;
      }
    }
  }
  return out;
}

/** CKL-U009 — HEAD and Range responses in a shared store. */
export function methodAndRangeConfusion(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  for (const entry of ctx.entries) {
    const store = storability(entry.request, entry.response);
    if (!store.mayStore) continue;
    const vary = parseVary(entry.response.headers);
    if (entry.request.method === 'HEAD') {
      const siblingGet = ctx.entries.find(
        (e) => e.index !== entry.index && e.request.method === 'GET' && e.request.url === entry.request.url,
      );
      out.push(
        makeFinding('CKL-U009', {
          resource: resourceLabel(entry),
          summary: `A HEAD response for this URL is storable by a shared cache (${store.reason}). The method is not part of any Vary list and some caches do not include it in the key, in which case a later GET is answered with this bodyless response.`,
          kind: 'inference',
          confidence: siblingGet === undefined ? 0.4 : 0.55,
          evidence: [
            ev('method', 'HEAD'),
            ev('storability', store.reason),
            ...(siblingGet === undefined
              ? [ev('note', 'no GET to the same URL is in the capture, so the two cannot be compared here')]
              : [ev('matching GET', `entry ${siblingGet.index} is a GET to the same URL`)]),
            ev(
              'why this is an inference',
              'whether the method is in the key is a property of the cache, not of the response; `plan` emits the HEAD-then-GET pair that settles it',
            ),
          ],
          entries: siblingGet === undefined ? [entry.index] : [entry.index, siblingGet.index],
        }),
      );
      continue;
    }
    const rangeRequested = headerValue(entry.request.headers, 'range');
    if (entry.response.status === 206 || rangeRequested !== null) {
      if (vary.includes('range')) continue;
      out.push(
        makeFinding('CKL-U009', {
          resource: resourceLabel(entry),
          summary: `A ranged request produced a ${entry.response.status} that a shared cache may store (${store.reason}), and no response declares Vary: Range. A cache that keys without the Range header can answer a full GET with this partial content.`,
          kind: 'inference',
          confidence: 0.5,
          evidence: [
            ev('request', `Range: ${rangeRequested ?? '(absent, but the response is 206)'}`),
            ev('status', String(entry.response.status)),
            ev('Vary', vary.length === 0 ? 'no Vary header' : `Vary: ${vary.join(', ')} — Range is not listed`),
            ev('storability', store.reason),
            ev(
              'why this is an inference',
              'whether Range is in the key is a property of the cache; `plan` emits the ranged-then-full pair that settles it',
            ),
          ],
          entries: [entry.index],
        }),
      );
    }
  }
  return out;
}

/** CKL-U010 — a GET whose body changes the response. */
export function fatGet(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  for (const group of ctx.groups) {
    let reported = false;
    for (const [a, b] of pairs(group.entries)) {
      const delta = requestDelta(a, b);
      if (delta.dimensions !== 1 || !delta.bodyDiffers) continue;
      if (!['GET', 'HEAD'].includes(a.request.method) || a.request.method !== b.request.method) continue;
      const rdelta = responseDelta(a, b, ctx.normalisers);
      if (!rdelta.varied) continue;
      reported = true;
      out.push(
        makeFinding('CKL-U010', {
          resource: `${a.request.method} ${group.key}`,
          summary: `Two ${a.request.method} requests to this URL differ only in their request body and returned different responses. No cache keys on a GET body, so the body is an input that is entirely invisible to the key.`,
          kind: 'proof',
          evidence: [
            ev('single-variable pair', `entries ${a.index} and ${b.index} differ only in the request body`),
            ev('bodies', `${(a.request.body ?? '').length} bytes vs ${(b.request.body ?? '').length} bytes`),
            ev('response changed', rdelta.bodyDiffers ? 'the normalised bodies differ' : `response header(s) ${rdelta.headers.join(', ')} differ`),
          ],
          entries: [a.index, b.index],
        }),
      );
    }
    if (reported) continue;
    for (const entry of group.entries) {
      if (!['GET', 'HEAD'].includes(entry.request.method)) continue;
      const body = entry.request.body ?? '';
      if (body.trim() === '') continue;
      const store = storability(entry.request, entry.response);
      out.push(
        makeFinding('CKL-U010', {
          resource: resourceLabel(entry),
          summary: `A ${entry.request.method} request carried a ${body.length}-byte body. Only one observation is present, so the tool cannot show the body changed the response — but if the origin reads it, that input is unkeyed by construction.`,
          kind: 'inference',
          confidence: 0.4,
          severity: 'medium',
          evidence: [
            ev('request body', `${body.length} bytes on a ${entry.request.method}`),
            ev('storability', store.reason),
            ev(
              'why this is an inference',
              'a second observation with a different body is needed to show the origin reads it; `plan` emits that pair',
            ),
          ],
          entries: [entry.index],
        }),
      );
    }
  }
  return out;
}

export const UNKEYED_RULES = [
  unkeyedHeader,
  reflectedRoutingHeader,
  unkeyedQueryParameter,
  queryNormalisationDisagreement,
  unkeyedCookie,
  varyProblems,
  methodAndRangeConfusion,
  fatGet,
] as const;
