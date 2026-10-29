/**
 * `plan` — the request matrix that resolves a key.
 *
 * The lint half of this tool can only report what a capture already shows. To
 * find out what is actually in the key you have to send requests, and the
 * order and hygiene of those requests is the whole game: every probe gets its
 * own cache-buster so that a poisoned entry lands on a key nobody else will
 * ever request.
 */

import { ROUTING_HEADERS, makeHeader, parseCookieHeader } from './headers.js';
import { groupByResource } from './group.js';
import { inferKey } from './key.js';
import { NormaliserSet } from './normalise.js';
import type { CaptureEntry, Plan, PlanProbe } from './types.js';
import { DELIMITERS, parseUrl, serialiseQuery } from './url.js';
import { TOOL, VERSION } from './version.js';

export const BUSTER_PARAM = 'cklcb';

/**
 * The warning that has to be read before the matrix is sent. A probe without a
 * cache-buster does not test a cache, it modifies one — and on a production
 * CDN that means serving your payload to real users until the entry expires or
 * someone purges it.
 */
export const CACHE_BUSTER_WARNING: readonly string[] = [
  'Every probe below carries a unique cache-buster parameter. Keep it.',
  `A probe sent without one is not a test: if the input turns out to be unkeyed, the response is stored under the key real users request, and every one of them receives your payload until the entry expires or the cache is purged. That is a production incident caused by the test, not by the bug.`,
  'Send each probe twice — once to store, once to confirm the stored copy comes back — and confirm with the cache-status header, not with the body alone.',
  'Change one thing per probe. A probe that differs in two components tells you nothing about either.',
  'When a probe does poison its own buster key, note the key and the expiry, and say so in the report: the reviewer needs to know what was left behind.',
  'Scope and authorisation come first. A cache sits in front of other people’s traffic, so the blast radius of a mistake here is not limited to your own account.',
];

function withBuster(url: string, token: string): string {
  const u = parseUrl(url);
  const params = [...u.params, { name: BUSTER_PARAM, value: token, semicolon: false }];
  const search = serialiseQuery(params);
  return `${u.origin}${u.path}?${search}`;
}

function pathWithSuffix(url: string, delimiter: string, suffix: string, token: string): string {
  const u = parseUrl(url);
  const base = `${u.origin}${u.path}${delimiter}${suffix}`;
  const search = serialiseQuery([...u.params, { name: BUSTER_PARAM, value: token, semicolon: false }]);
  return `${base}?${search}`;
}

/**
 * Build the matrix. `target` is a URL; when the capture contains it, the
 * capture's own parameters and cookies are reused so the probes resemble real
 * traffic rather than a generic list.
 */
export function buildPlan(
  target: string,
  entries: readonly CaptureEntry[],
  options: { readonly buster?: string } = {},
): Plan {
  const prefix = options.buster ?? 'ckl';
  let counter = 0;
  const next = (): string => {
    counter += 1;
    return `${prefix}${String(counter).padStart(3, '0')}`;
  };

  const targetUrl = parseUrl(target);
  const matching = entries.filter((e) => {
    const u = parseUrl(e.request.url);
    return u.host === targetUrl.host && u.path === targetUrl.path;
  });
  const method = matching[0]?.request.method ?? 'GET';
  const probes: PlanProbe[] = [];

  probes.push({
    group: 'baseline',
    method,
    url: withBuster(target, next()),
    headers: [],
    purpose: 'Establish that the cache-buster parameter produces a key of its own.',
    expect:
      'first request a miss, second request a hit on the same buster value. If the second is also a miss the resource is not cached at all and nothing below will tell you anything; if the first is a hit the buster is being stripped and you need a different one.',
  });

  const extraHeaders = [
    { name: 'Host', why: 'the keyed host itself — worth one probe to see whether the edge routes on it or on SNI' },
    { name: 'X-Forwarded-For', why: 'geo and rate-limit branching' },
    { name: 'Accept', why: 'content negotiation that is often absent from Vary' },
    { name: 'Origin', why: 'reflected into Access-Control-Allow-Origin, which is then stored' },
    { name: 'Referer', why: 'echoed into analytics snippets and sometimes into links' },
    { name: 'True-Client-IP', why: 'CDN-specific client address header' },
    { name: 'X-Forwarded-SSL', why: 'another scheme hint' },
    { name: 'X-Timer', why: 'control probe: a header the origin should not read at all' },
  ];
  for (const h of [...ROUTING_HEADERS, ...extraHeaders]) {
    const token = next();
    probes.push({
      group: 'unkeyed-header',
      method,
      url: withBuster(target, token),
      headers: [makeHeader(h.name, `ckl-${token}.invalid`)],
      purpose: `Does the response change with ${h.name}? ${h.why}.`,
      expect: `a reflection of ckl-${token}.invalid in the body, a Location, a script src, a canonical link or an og: tag; or any other difference against the baseline. Then re-request without the header on the same buster value: if the reflection persists, the header is unkeyed.`,
    });
  }

  for (const delimiter of DELIMITERS) {
    for (const suffix of ['ckl.css', 'ckl.js']) {
      const token = next();
      probes.push({
        group: 'delimiter',
        method,
        url: pathWithSuffix(target, delimiter.token, suffix, token),
        headers: [],
        purpose: `Does the origin still serve the target resource when the path is followed by "${delimiter.token}${suffix}"? ${delimiter.label}: ${delimiter.why}.`,
        expect:
          'the target resource’s own content under a path the cache treats as static. Check the cache-status header on a second request from a session with no credentials at all — that second request is what shows the content was stored.',
      });
    }
  }

  const sampleParam = matching
    .flatMap((e) => parseUrl(e.request.url).params)
    .find((p) => p.name !== BUSTER_PARAM);
  const paramName = sampleParam?.name ?? 'lang';
  const paramValue = sampleParam?.value ?? 'en';
  const permutations: { label: string; search: (token: string) => string; why: string }[] = [
    {
      label: 'parameter order',
      search: (t) => `${BUSTER_PARAM}=${t}&${paramName}=${paramValue}`,
      why: 'a cache that sorts the query and an origin that does not, or the reverse, see different keys for one request',
    },
    {
      label: 'duplicate parameter',
      search: (t) => `${paramName}=${paramValue}&${paramName}=ckl&${BUSTER_PARAM}=${t}`,
      why: 'first-wins, last-wins and join-all are all implemented somewhere',
    },
    {
      label: 'name case',
      search: (t) => `${paramName.toUpperCase()}=${paramValue}&${BUSTER_PARAM}=${t}`,
      why: 'parameter names are case-sensitive in the RFC and case-insensitive in several frameworks',
    },
    {
      label: 'semicolon separator',
      search: (t) => `${paramName}=${paramValue};${paramName}=ckl&${BUSTER_PARAM}=${t}`,
      why: 'a `;`-joined pair is one parameter to most caches and two to several frameworks',
    },
    {
      label: 'empty parameter',
      search: (t) => `${paramName}&${BUSTER_PARAM}=${t}`,
      why: 'a valueless parameter is dropped by some normalisers and kept by others',
    },
    {
      label: 'encoded hash',
      search: (t) => `${paramName}=${paramValue}%23ckl&${BUSTER_PARAM}=${t}`,
      why: 'the origin may decode %23 and truncate; the cache keeps the encoded bytes',
    },
    {
      label: 'buster only, no other parameters',
      search: (t) => `${BUSTER_PARAM}=${t}`,
      why: 'establishes whether the query is in the key at all',
    },
  ];
  for (const perm of permutations) {
    const token = next();
    probes.push({
      group: 'query-permutation',
      method,
      url: `${targetUrl.origin}${targetUrl.path}?${perm.search(token)}`,
      headers: [],
      purpose: `Query ${perm.label}: ${perm.why}.`,
      expect:
        'compare the body against the baseline, then compare the cache-status header. A hit on a spelling you have not sent before means the cache canonicalised it into another key.',
    });
  }

  const cookieNames = [
    ...new Set(matching.flatMap((e) => [...parseCookieHeader(e.request.headers).keys()])),
  ];
  const cookieToken = next();
  probes.push({
    group: 'cookie',
    method,
    url: withBuster(target, cookieToken),
    headers: [makeHeader('Cookie', `${cookieNames[0] ?? 'session'}=CKL-PROBE-${cookieToken}`)],
    purpose:
      cookieNames.length > 0
        ? `Does the response depend on ${cookieNames.join(', ')} while Vary: Cookie is absent?`
        : 'Does the response depend on a cookie while Vary: Cookie is absent?',
    expect:
      'send this probe, then request the same buster value with no Cookie header at all. If the cookie-dependent body comes back, the cookie is not in the key — which on an authenticated resource is the whole finding.',
  });

  const headToken = next();
  probes.push({
    group: 'method-and-range',
    method: 'HEAD',
    url: withBuster(target, headToken),
    headers: [],
    purpose: 'Is the request method part of the key?',
    expect: `send this HEAD, then a GET to the same buster value (${headToken}). A bodyless or zero-length GET response means the HEAD was stored under a key the GET matched.`,
  });
  const rangeToken = next();
  probes.push({
    group: 'method-and-range',
    method: 'GET',
    url: withBuster(target, rangeToken),
    headers: [makeHeader('Range', 'bytes=0-1')],
    purpose: 'Is the Range header part of the key?',
    expect: `send this ranged request, then a full GET to the same buster value (${rangeToken}). A 206 or a two-byte body for the full GET means Range was not in the key.`,
  });

  const fatToken = next();
  probes.push({
    group: 'fat-get',
    method: 'GET',
    url: withBuster(target, fatToken),
    headers: [makeHeader('Content-Type', 'application/x-www-form-urlencoded'), makeHeader('Content-Length', '13')],
    purpose: 'Does the origin read a body on a GET? No cache keys on one.',
    expect:
      'send with the body `ckl=probe` and compare against the baseline. A difference means the origin reads an input that is invisible to every cache in the path.',
  });

  const notes: string[] = [];
  if (matching.length === 0) {
    notes.push(
      'The capture contains no entry for this URL, so the matrix is the generic one — no parameters, cookies or methods were taken from observed traffic.',
    );
  } else {
    const groups = groupByResource(matching);
    const group = groups[0];
    if (group !== undefined) {
      const key = inferKey(group, NormaliserSet.default());
      notes.push(
        `${matching.length} observation${matching.length === 1 ? '' : 's'} of this resource in the capture; inferred key confidence ${key.confidence.toFixed(2)}.`,
      );
      if (key.inKey.length > 0) notes.push(`Evidence already places in the key: ${key.inKey.map((c) => c.component).join(', ')}.`);
      if (key.notInKey.length > 0) {
        notes.push(`Evidence already suggests these are not in the key: ${key.notInKey.map((c) => c.component).join(', ')} — confirm these first.`);
      }
      if (key.unknown.length > 0) notes.push(`Untested in the capture: ${key.unknown.map((c) => c.component).join(', ')}.`);
    }
  }

  return {
    tool: TOOL,
    version: VERSION,
    target,
    buster: `${BUSTER_PARAM}=${prefix}NNN, unique per probe`,
    warning: CACHE_BUSTER_WARNING,
    probes,
    notesFromCapture: notes,
  };
}
