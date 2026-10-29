/**
 * URL and path modelling.
 *
 * Both halves of this bug class are disagreements about what identifies a
 * resource, so the tool has to be explicit about every transformation a cache
 * or an origin might apply to a path or a query string, rather than relying on
 * one parser's opinion.
 */

export interface QueryParam {
  readonly name: string;
  readonly value: string;
  /** True when the parameter was separated by `;` rather than `&`. */
  readonly semicolon: boolean;
}

export interface ParsedUrl {
  readonly raw: string;
  /** scheme://host[:port], or the empty string for a path-only capture entry. */
  readonly origin: string;
  readonly host: string;
  readonly path: string;
  /** Query string without the leading `?`. */
  readonly search: string;
  /** Fragment without the leading `#`. Captures rarely carry one; a literal `%23` does not land here. */
  readonly fragment: string;
  readonly params: readonly QueryParam[];
}

export function parseUrl(raw: string): ParsedUrl {
  let origin = '';
  let host = '';
  let rest = raw;
  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(raw);
  if (schemeMatch !== null) {
    const afterScheme = raw.slice(schemeMatch[0].length);
    const slash = afterScheme.search(/[/?#]/);
    const authority = slash === -1 ? afterScheme : afterScheme.slice(0, slash);
    origin = `${schemeMatch[1] ?? ''}://${authority}`;
    host = authority.toLowerCase();
    rest = slash === -1 ? '/' : afterScheme.slice(slash);
  }
  let fragment = '';
  const hash = rest.indexOf('#');
  if (hash !== -1) {
    fragment = rest.slice(hash + 1);
    rest = rest.slice(0, hash);
  }
  let search = '';
  const q = rest.indexOf('?');
  if (q !== -1) {
    search = rest.slice(q + 1);
    rest = rest.slice(0, q);
  }
  const path = rest === '' ? '/' : rest;
  return { raw, origin, host, path, search, fragment, params: parseQuery(search) };
}

/**
 * Parse a query string preserving order and duplicates, and recording which
 * separator was used. `;` as a separator is the interesting case: it was in
 * the HTML 4 recommendation, several frameworks still honour it, and most
 * caches do not — so `?a=1;b=2` can be one parameter to the cache and two to
 * the origin.
 */
export function parseQuery(search: string): QueryParam[] {
  if (search === '') return [];
  const out: QueryParam[] = [];
  for (const ampPart of search.split('&')) {
    const semiParts = ampPart.split(';');
    semiParts.forEach((part, i) => {
      if (part === '' && semiParts.length === 1 && ampPart === '') return;
      const eq = part.indexOf('=');
      const name = eq === -1 ? part : part.slice(0, eq);
      const value = eq === -1 ? '' : part.slice(eq + 1);
      out.push({ name, value, semicolon: i > 0 });
    });
  }
  return out.filter((p) => !(p.name === '' && p.value === ''));
}

export function serialiseQuery(params: readonly QueryParam[]): string {
  return params.map((p) => (p.value === '' ? p.name : `${p.name}=${p.value}`)).join('&');
}

/** Sorted by name then value — the normalisation a careful cache would apply. */
export function canonicalQuery(params: readonly QueryParam[]): string {
  const sorted = [...params].sort((a, b) =>
    a.name === b.name ? a.value.localeCompare(b.value) : a.name.localeCompare(b.name),
  );
  return serialiseQuery(sorted);
}

/** Resource identity for grouping: method is handled by the caller. */
export function resourceKey(url: ParsedUrl): string {
  return `${url.host}${url.path}`;
}

export const STATIC_EXTENSIONS: readonly string[] = [
  'css',
  'js',
  'mjs',
  'cjs',
  'map',
  'json',
  'jpg',
  'jpeg',
  'png',
  'gif',
  'svg',
  'webp',
  'avif',
  'ico',
  'bmp',
  'woff',
  'woff2',
  'ttf',
  'eot',
  'otf',
  'txt',
  'xml',
  'pdf',
  'mp4',
  'webm',
  'mp3',
  'zip',
  'gz',
];

export const STATIC_PREFIXES: readonly string[] = [
  '/static/',
  '/assets/',
  '/public/',
  '/_next/static/',
  '/_nuxt/',
  '/dist/',
  '/build/',
  '/media/',
  '/images/',
  '/img/',
  '/css/',
  '/js/',
  '/fonts/',
];

/** The extension a by-extension cache rule would see, or `null`. */
export function cacheVisibleExtension(path: string): string | null {
  const seg = path.slice(path.lastIndexOf('/') + 1);
  const dot = seg.lastIndexOf('.');
  if (dot <= 0) return null;
  const ext = seg.slice(dot + 1).toLowerCase();
  if (!/^[a-z0-9]{1,8}$/.test(ext)) return null;
  return ext;
}

export function looksStaticToCache(path: string): { static: boolean; why: string } {
  const ext = cacheVisibleExtension(path);
  if (ext !== null && STATIC_EXTENSIONS.includes(ext)) {
    return { static: true, why: `path ends in .${ext}, which by-extension cache rules treat as static` };
  }
  const lower = path.toLowerCase();
  for (const prefix of STATIC_PREFIXES) {
    if (lower.startsWith(prefix)) {
      return { static: true, why: `path is under ${prefix}, a conventional static prefix` };
    }
  }
  return { static: false, why: '' };
}

export interface Delimiter {
  readonly token: string;
  readonly label: string;
  /** What has to be true at the origin for this delimiter to be ignored. */
  readonly why: string;
}

/**
 * The delimiter matrix. Each entry is a byte sequence that one of the two
 * parsers may treat as ending the resource name while the other treats it as
 * part of the name. That asymmetry is the whole of cache deception.
 */
export const DELIMITERS: readonly Delimiter[] = [
  { token: '.', label: 'dot (extension suffix)', why: 'route matches a prefix, or the framework strips a trailing extension / format suffix' },
  { token: '/', label: 'trailing slash segment', why: 'router tolerates an extra path segment and ignores it, e.g. a greedy or optional route parameter' },
  { token: '%2F', label: 'encoded slash', why: 'origin decodes %2F before routing while the cache keys on the raw bytes' },
  { token: '//', label: 'doubled slash', why: 'origin collapses empty path segments; the cache does not, so the two see different paths' },
  { token: ';', label: 'path parameter (matrix parameter)', why: 'Java/Spring-style path parameters, and some proxies, discard everything after `;`' },
  { token: '%3B', label: 'encoded semicolon', why: 'as above, but reached after the origin percent-decodes' },
  { token: '?', label: 'query start', why: 'the cache has been configured to key on the full URL including query, or to ignore it entirely' },
  { token: '%23', label: 'encoded hash', why: 'origin decodes %23 to `#` and truncates the path there; the cache keeps the encoded bytes' },
  { token: '..%2f', label: 'encoded dot-segment', why: 'origin decodes then resolves `..`, escaping a static prefix the cache matched on' },
];

/**
 * Split a path at every delimiter occurrence, yielding the candidate base the
 * origin might have routed to and the suffix the cache saw.
 */
export interface DelimiterSplit {
  readonly delimiter: Delimiter;
  readonly base: string;
  readonly suffix: string;
}

export function delimiterSplits(path: string): DelimiterSplit[] {
  const out: DelimiterSplit[] = [];
  const lower = path.toLowerCase();
  for (const delimiter of DELIMITERS) {
    const token = delimiter.token.toLowerCase();
    let from = 0;
    for (;;) {
      const at = lower.indexOf(token, from);
      if (at === -1 || at === 0) {
        if (at === 0) {
          from = 1;
          continue;
        }
        break;
      }
      const base = path.slice(0, at);
      const suffix = path.slice(at + token.length);
      if (base !== '' && base !== '/') out.push({ delimiter, base, suffix });
      from = at + 1;
    }
  }
  return out;
}

/** Percent-decode once, tolerating malformed sequences rather than throwing. */
export function decodeOnce(path: string): string {
  return path.replace(/%[0-9a-f]{2}/gi, (m) => {
    const code = Number.parseInt(m.slice(1), 16);
    return code === 0 ? m : String.fromCharCode(code);
  });
}

/** Resolve `.` and `..` segments the way a server-side router would. */
export function resolveDotSegments(path: string): string {
  const leadingSlash = path.startsWith('/');
  const out: string[] = [];
  for (const seg of path.split('/')) {
    if (seg === '.' || seg === '') continue;
    if (seg === '..') {
      out.pop();
      continue;
    }
    out.push(seg);
  }
  const joined = out.join('/');
  const trailing = path.endsWith('/') && joined !== '' ? '/' : '';
  return `${leadingSlash ? '/' : ''}${joined}${trailing}`;
}

export interface OriginCandidate {
  readonly path: string;
  readonly via: readonly string[];
}

/**
 * Every path the origin might plausibly resolve `path` to, each tagged with
 * the transformations that got there. Used to ask the one question that
 * matters for deception: did the cache store something under a static-looking
 * key that the origin actually served from a dynamic route?
 *
 * This is a model of *plausible* server behaviour, not a claim about any
 * specific server — findings derived from it are labelled as inferences
 * unless the capture also shows the origin returning the dynamic resource.
 */
export function originCandidates(path: string, maxDepth = 4): OriginCandidate[] {
  const steps: { id: string; apply: (p: string) => string }[] = [
    { id: 'percent-decode', apply: decodeOnce },
    { id: 'collapse-slashes', apply: (p) => p.replace(/\/{2,}/g, '/') },
    { id: 'resolve-dot-segments', apply: resolveDotSegments },
    { id: 'strip-path-params', apply: (p) => p.replace(/;[^/]*/g, '') },
    { id: 'truncate-at-hash', apply: (p) => (p.includes('#') ? p.slice(0, p.indexOf('#')) : p) },
    {
      id: 'strip-static-extension',
      apply: (p) => {
        const ext = cacheVisibleExtension(p);
        if (ext === null || !STATIC_EXTENSIONS.includes(ext)) return p;
        return p.slice(0, p.length - ext.length - 1);
      },
    },
    { id: 'strip-trailing-slash', apply: (p) => (p.length > 1 && p.endsWith('/') ? p.slice(0, -1) : p) },
  ];

  const seen = new Map<string, string[]>();
  seen.set(path, []);
  let frontier: OriginCandidate[] = [{ path, via: [] }];
  for (let depth = 0; depth < maxDepth; depth += 1) {
    const next: OriginCandidate[] = [];
    for (const cand of frontier) {
      for (const step of steps) {
        if (cand.via.includes(step.id)) continue;
        const applied = step.apply(cand.path);
        if (applied === cand.path || applied === '') continue;
        if (seen.has(applied)) continue;
        const via = [...cand.via, step.id];
        seen.set(applied, via);
        next.push({ path: applied, via });
      }
    }
    if (next.length === 0) break;
    frontier = next;
  }
  return [...seen.entries()].map(([p, via]) => ({ path: p, via }));
}
