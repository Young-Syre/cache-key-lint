/**
 * Grouping and principled diffing.
 *
 * Everything the tool infers about a key comes from comparing two observations
 * of the same resource that differ in exactly one request component. A pair
 * that differs in two things proves nothing about either, so those pairs are
 * recorded as unattributable rather than guessed at.
 */

import { CACHE_STATUS_LOWER, cacheVendor, foldHeaders, isHitValue, parseCookieHeader } from './headers.js';
import type { NormaliserSet } from './normalise.js';
import type { CaptureEntry, HeaderPair } from './types.js';
import { canonicalQuery, parseUrl, type ParsedUrl } from './url.js';

/** Request headers that are transport or capture noise, never a cache input worth attributing. */
export const IGNORED_REQUEST_HEADERS: readonly string[] = [
  'content-length',
  'connection',
  'keep-alive',
  'te',
  'transfer-encoding',
  'upgrade',
  'proxy-connection',
  'date',
  'if-none-match',
  'if-modified-since',
  'if-match',
  'if-unmodified-since',
  'priority',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'sec-fetch-user',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'upgrade-insecure-requests',
  'cache-control',
  'pragma',
];

/** Response headers whose change means the response really did vary. */
export const SIGNIFICANT_RESPONSE_HEADERS: readonly string[] = [
  'location',
  'content-location',
  'content-language',
  'content-type',
  'content-disposition',
  'link',
  'refresh',
  'content-security-policy',
  'access-control-allow-origin',
];

export interface ResourceGroup {
  /** `host/path`, the identity a cache that keys on host and path would use. */
  readonly key: string;
  readonly host: string;
  readonly path: string;
  readonly entries: readonly CaptureEntry[];
}

export function groupByResource(entries: readonly CaptureEntry[]): ResourceGroup[] {
  const map = new Map<string, CaptureEntry[]>();
  for (const e of entries) {
    const u = parseUrl(e.request.url);
    const key = `${u.host}${u.path}`;
    const list = map.get(key);
    if (list === undefined) map.set(key, [e]);
    else list.push(e);
  }
  return [...map.entries()]
    .map(([key, list]) => {
      const u = parseUrl((list[0] as CaptureEntry).request.url);
      return { key, host: u.host, path: u.path, entries: list };
    })
    .sort((a, b) => a.key.localeCompare(b.key));
}

export interface QueryDiff {
  readonly name: string;
  readonly a: string | null;
  readonly b: string | null;
}

/** The query-spelling classes that caches and origins normalise differently. */
export type QuerySpellingClass =
  | 'parameter-order'
  | 'duplicate-parameter'
  | 'name-case'
  | 'semicolon-separator'
  | 'empty-parameter'
  | 'encoded-hash';

export interface RequestDelta {
  /** Header names (lowercase) whose folded values differ. Excludes `cookie`. */
  readonly headers: readonly string[];
  /** Cookie names whose values differ, or which are present on only one side. */
  readonly cookies: readonly string[];
  readonly queryValues: readonly QueryDiff[];
  /** Same canonical query, different spelling. */
  readonly querySpelling: readonly QuerySpellingClass[];
  readonly methodDiffers: boolean;
  readonly bodyDiffers: boolean;
  /** Total number of independent request components that differ. */
  readonly dimensions: number;
}

function spellingClasses(a: ParsedUrl, b: ParsedUrl): QuerySpellingClass[] {
  const out = new Set<QuerySpellingClass>();
  if (a.search === b.search) return [];
  const namesA = a.params.map((p) => p.name);
  const namesB = b.params.map((p) => p.name);
  if (
    namesA.length === namesB.length &&
    [...namesA].sort().join(',') === [...namesB].sort().join(',') &&
    namesA.join(',') !== namesB.join(',')
  ) {
    out.add('parameter-order');
  }
  if (new Set(namesA).size !== namesA.length || new Set(namesB).size !== namesB.length) {
    out.add('duplicate-parameter');
  }
  if (
    namesA.join(',') !== namesB.join(',') &&
    namesA.join(',').toLowerCase() === namesB.join(',').toLowerCase()
  ) {
    out.add('name-case');
  }
  if (a.params.some((p) => p.semicolon) !== b.params.some((p) => p.semicolon)) {
    out.add('semicolon-separator');
  }
  if (
    a.params.some((p) => p.value === '' && !a.search.includes(`${p.name}=`)) !==
    b.params.some((p) => p.value === '' && !b.search.includes(`${p.name}=`))
  ) {
    out.add('empty-parameter');
  }
  if (/%23/i.test(a.search) !== /%23/i.test(b.search)) out.add('encoded-hash');
  return [...out];
}

export function requestDelta(a: CaptureEntry, b: CaptureEntry): RequestDelta {
  const foldedA = foldHeaders(a.request.headers);
  const foldedB = foldHeaders(b.request.headers);
  const names = new Set([...foldedA.keys(), ...foldedB.keys()]);
  const headers: string[] = [];
  for (const name of names) {
    if (IGNORED_REQUEST_HEADERS.includes(name)) continue;
    if (name === 'cookie') continue;
    if (foldedA.get(name) !== foldedB.get(name)) headers.push(name);
  }

  const cookiesA = parseCookieHeader(a.request.headers);
  const cookiesB = parseCookieHeader(b.request.headers);
  const cookieNames = new Set([...cookiesA.keys(), ...cookiesB.keys()]);
  const cookies: string[] = [];
  for (const name of cookieNames) {
    if (cookiesA.get(name) !== cookiesB.get(name)) cookies.push(name);
  }

  const urlA = parseUrl(a.request.url);
  const urlB = parseUrl(b.request.url);
  const queryValues: QueryDiff[] = [];
  const paramNames = new Set([...urlA.params.map((p) => p.name), ...urlB.params.map((p) => p.name)]);
  for (const name of paramNames) {
    const va = urlA.params.filter((p) => p.name === name).map((p) => p.value).join('|');
    const vb = urlB.params.filter((p) => p.name === name).map((p) => p.value).join('|');
    const hasA = urlA.params.some((p) => p.name === name);
    const hasB = urlB.params.some((p) => p.name === name);
    if (va !== vb) queryValues.push({ name, a: hasA ? va : null, b: hasB ? vb : null });
  }
  const querySpelling =
    canonicalQuery(urlA.params) === canonicalQuery(urlB.params) ? spellingClasses(urlA, urlB) : [];

  const methodDiffers = a.request.method !== b.request.method;
  const bodyDiffers = (a.request.body ?? '') !== (b.request.body ?? '');

  const dimensions =
    headers.length +
    cookies.length +
    queryValues.length +
    (querySpelling.length > 0 ? 1 : 0) +
    (methodDiffers ? 1 : 0) +
    (bodyDiffers ? 1 : 0);

  return { headers: headers.sort(), cookies: cookies.sort(), queryValues, querySpelling, methodDiffers, bodyDiffers, dimensions };
}

export interface ResponseDelta {
  readonly statusDiffers: boolean;
  readonly bodyDiffers: boolean;
  readonly headers: readonly string[];
  /** The response differed in a way that matters, once noise was normalised away. */
  readonly varied: boolean;
}

export function responseDelta(a: CaptureEntry, b: CaptureEntry, normalisers: NormaliserSet): ResponseDelta {
  const bodyDiffers = !normalisers.equivalent(a.response.body, b.response.body);
  const foldedA = foldHeaders(a.response.headers);
  const foldedB = foldHeaders(b.response.headers);
  const headers = SIGNIFICANT_RESPONSE_HEADERS.filter((name) => {
    const va = foldedA.get(name);
    const vb = foldedB.get(name);
    if (va === vb) return false;
    // A CSP that differs only by its nonce is not a variation.
    if (name === 'content-security-policy') {
      return normalisers.apply(va ?? '') !== normalisers.apply(vb ?? '');
    }
    return true;
  });
  const statusDiffers = a.response.status !== b.response.status;
  return { statusDiffers, bodyDiffers, headers, varied: statusDiffers || bodyDiffers || headers.length > 0 };
}

export interface CacheObservation {
  readonly header: HeaderPair;
  readonly vendor: string;
  readonly hit: boolean;
}

export function cacheObservations(entry: CaptureEntry): CacheObservation[] {
  return entry.response.headers
    .filter((h) => CACHE_STATUS_LOWER.includes(h.lower))
    .map((h) => ({ header: h, vendor: cacheVendor(h.lower), hit: isHitValue(h.lower, h.value) }));
}

export function anyHit(entry: CaptureEntry): CacheObservation | null {
  return cacheObservations(entry).find((o) => o.hit) ?? null;
}

/** All unordered pairs of a list, in capture order. */
export function pairs<T>(items: readonly T[]): [T, T][] {
  const out: [T, T][] = [];
  for (let i = 0; i < items.length; i += 1) {
    for (let j = i + 1; j < items.length; j += 1) {
      out.push([items[i] as T, items[j] as T]);
    }
  }
  return out;
}
