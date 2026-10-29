import type { FindingKind, Severity } from '../types.js';

export interface RuleMeta {
  readonly id: string;
  readonly name: string;
  readonly severity: Severity;
  /** The kind the rule produces when it has no supporting cache evidence. */
  readonly defaultKind: FindingKind;
  /** One sentence on why the disagreement exists, not on what the tool did. */
  readonly mechanism: string;
}

/**
 * The rule catalogue. `cache-key-lint rules` prints this table, and the README
 * table is that command's output — so the two cannot drift apart.
 */
export const RULES: readonly RuleMeta[] = [
  // --- unkeyed input: cache poisoning ------------------------------------
  {
    id: 'CKL-U001',
    name: 'Response varies with a request header absent from Vary',
    severity: 'high',
    defaultKind: 'inference',
    mechanism:
      'The header reaches the origin and changes the response, but nothing tells the cache to include it in the key, so one request stores a response that every later request receives.',
  },
  {
    id: 'CKL-U002',
    name: 'Routing header reflected into the response',
    severity: 'high',
    defaultKind: 'proof',
    mechanism:
      'Frameworks build absolute URLs from X-Forwarded-* and Forwarded rather than from the Host they were keyed on, so an attacker-supplied host lands in a script src, a Location or a canonical link.',
  },
  {
    id: 'CKL-U003',
    name: 'Response varies with a query parameter the cache may exclude',
    severity: 'high',
    defaultKind: 'inference',
    mechanism:
      'Caches are routinely configured to ignore query parameters, or to key on an allow-list of them, while the origin branches on every one it receives.',
  },
  {
    id: 'CKL-U004',
    name: 'Cache and origin disagree on query normalisation',
    severity: 'medium',
    defaultKind: 'inference',
    mechanism:
      'Parameter order, duplicate names, name case, `;` separators and empty parameters are each normalised differently by caches and origins, so two spellings of one query can be one key and two responses.',
  },
  {
    id: 'CKL-U005',
    name: 'Response varies with a cookie while Vary: Cookie is absent',
    severity: 'high',
    defaultKind: 'inference',
    mechanism:
      'Cookies are per-user by construction and are almost never in a CDN key, so a response that depends on one is a response served to the wrong user.',
  },
  {
    id: 'CKL-U006',
    name: 'Vary: * on a cacheable response',
    severity: 'low',
    defaultKind: 'proof',
    mechanism:
      'Vary: * means no request can ever match a stored response, so either the caching is pointless or an intermediary is ignoring the header — and which of the two is true is unknowable from the response alone.',
  },
  {
    id: 'CKL-U007',
    name: 'Vary names a header the origin does not read',
    severity: 'low',
    defaultKind: 'inference',
    mechanism:
      'A Vary token that does not affect the response fragments the cache for no benefit, and hides the fact that the header which does affect it is missing from the list.',
  },
  {
    id: 'CKL-U008',
    name: 'Vary: User-Agent',
    severity: 'low',
    defaultKind: 'proof',
    mechanism:
      'User-Agent has effectively unbounded cardinality, so caches normalise or drop it; relying on it to separate responses means relying on behaviour the cache does not promise.',
  },
  {
    id: 'CKL-U009',
    name: 'HEAD or Range response may be stored under a key a GET would hit',
    severity: 'medium',
    defaultKind: 'inference',
    mechanism:
      'The request method and the Range header are part of the request but not always part of the key, so a bodyless or partial response can be returned for a full GET.',
  },
  {
    id: 'CKL-U010',
    name: 'Fat GET: a request body changes a GET response',
    severity: 'high',
    defaultKind: 'proof',
    mechanism:
      'No cache keys on a GET request body, so if the origin reads one it is reading an input that is completely invisible to the key.',
  },

  // --- keyed but ignored: cache deception --------------------------------
  {
    id: 'CKL-D001',
    name: 'Static extension suffix resolves to a dynamic resource',
    severity: 'high',
    defaultKind: 'inference',
    mechanism:
      'The cache decides what is static from the path suffix while the origin decides what to serve from its router, and routers commonly ignore a trailing extension.',
  },
  {
    id: 'CKL-D002',
    name: 'Origin tolerates a path delimiter the cache keys on',
    severity: 'medium',
    defaultKind: 'proof',
    mechanism:
      'Each delimiter is a byte sequence one parser treats as ending the resource name and the other treats as part of it; that asymmetry is what makes a suffix reachable.',
  },
  {
    id: 'CKL-D003',
    name: 'Static-prefix escape via path normalisation',
    severity: 'high',
    defaultKind: 'inference',
    mechanism:
      'A cache rule that matches /static/ on the raw path can be satisfied by a path the origin percent-decodes and resolves back out of that directory.',
  },
  {
    id: 'CKL-D004',
    name: 'Cacheable response on a user-specific resource',
    severity: 'critical',
    defaultKind: 'inference',
    mechanism:
      'Caching is per-resource and authentication is per-user, so a response that identifies a user and is storable by a shared cache will be handed to whoever asks next.',
  },
  {
    id: 'CKL-D005',
    name: 'Cache and origin disagree on path normalisation',
    severity: 'medium',
    defaultKind: 'inference',
    mechanism:
      'Two spellings of one path are two keys to a cache that compares bytes and one resource to an origin that normalises first, which both splits the cache and creates a key an attacker can choose.',
  },

  // --- Cache-Control directive contradictions ---------------------------
  {
    id: 'CKL-C001',
    name: 'private combined with a positive max-age',
    severity: 'medium',
    defaultKind: 'proof',
    mechanism:
      'private restricts storage to one user and max-age invites storage; an intermediary that honours only the freshness half stores a private response.',
  },
  {
    id: 'CKL-C002',
    name: 'no-cache without no-store on an authenticated response',
    severity: 'medium',
    defaultKind: 'proof',
    mechanism:
      'no-cache permits storing the response and only requires revalidation before reuse, so the body sits in a shared cache and a failed or skipped revalidation serves it.',
  },
  {
    id: 'CKL-C003',
    name: 's-maxage overrides a restrictive max-age',
    severity: 'high',
    defaultKind: 'proof',
    mechanism:
      's-maxage applies to shared caches and takes precedence there, so a carefully chosen max-age=0 protects browsers while the CDN keeps the response for as long as s-maxage says.',
  },
  {
    id: 'CKL-C004',
    name: 'Revalidation requested without must-revalidate',
    severity: 'low',
    defaultKind: 'proof',
    mechanism:
      'Without must-revalidate (or proxy-revalidate) a cache is permitted to serve a stale stored response when the origin cannot be reached, which is exactly when stale data is most harmful.',
  },
  {
    id: 'CKL-C005',
    name: 'stale-while-revalidate or stale-if-error extends the exposure window',
    severity: 'medium',
    defaultKind: 'proof',
    mechanism:
      'Both extensions license serving a stored response after it has expired, so a poisoned or private entry outlives its max-age by the stale window.',
  },
  {
    id: 'CKL-C006',
    name: 'Pragma: no-cache relied on alone',
    severity: 'medium',
    defaultKind: 'proof',
    mechanism:
      'Pragma is an HTTP/1.0 request-header compatibility feature; as a response header it has no defined effect, so a response carrying only Pragma is uncontrolled.',
  },
  {
    id: 'CKL-C007',
    name: 'No Cache-Control on a heuristically cacheable response',
    severity: 'medium',
    defaultKind: 'proof',
    mechanism:
      'RFC 9111 lets a cache store and reuse a response with no explicit freshness information by guessing one, so silence is not the same as "do not cache".',
  },

  // --- capture evidence -------------------------------------------------
  {
    id: 'CKL-E001',
    name: 'Cache reported a HIT on a response that should not be stored',
    severity: 'critical',
    defaultKind: 'proof',
    mechanism:
      'A hit status from the serving cache is the one piece of evidence that settles the argument: the response was stored, and it was reused.',
  },
  {
    id: 'CKL-E002',
    name: 'Nonzero Age on a response carrying a user identifier',
    severity: 'high',
    defaultKind: 'proof',
    mechanism:
      'Age is the time a shared cache has held the response, so any positive value on a per-user response means the response is already in a shared store.',
  },
] as const;

const BY_ID = new Map(RULES.map((r) => [r.id, r]));

export function rule(id: string): RuleMeta {
  const meta = BY_ID.get(id);
  if (meta === undefined) throw new Error(`unknown rule id: ${id}`);
  return meta;
}

export function ruleIds(): string[] {
  return RULES.map((r) => r.id);
}
