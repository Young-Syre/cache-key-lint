/**
 * Keyed but ignored — the cache-deception half.
 *
 * Here the attacker does not change a header; they change the URL so that the
 * cache and the origin disagree about what resource it names. The cache sees
 * something static and stores it. The origin sees an authenticated page and
 * serves it. The report therefore has to say which transformation produced the
 * disagreement, and what in the stored response identified a user.
 */

import { anyHit } from '../group.js';
import { describeIdentity, hasProof, identitySignals } from '../identity.js';
import { storability } from '../policy.js';
import type { CaptureEntry, Finding } from '../types.js';
import {
  DELIMITERS,
  delimiterSplits,
  looksStaticToCache,
  originCandidates,
  parseUrl,
  STATIC_PREFIXES,
} from '../url.js';
import { ev, makeFinding, resourceLabel, type RuleContext } from './util.js';

interface Located {
  readonly host: string;
  readonly path: string;
  readonly entries: readonly CaptureEntry[];
}

function pathIndex(ctx: RuleContext): Map<string, Map<string, Located>> {
  const out = new Map<string, Map<string, Located>>();
  for (const group of ctx.groups) {
    let byPath = out.get(group.host);
    if (byPath === undefined) {
      byPath = new Map();
      out.set(group.host, byPath);
    }
    byPath.set(group.path, { host: group.host, path: group.path, entries: group.entries });
  }
  return out;
}

/** CKL-D001 — a static-looking suffix that the origin resolves to something dynamic. */
export function staticSuffixDeception(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const index = pathIndex(ctx);
  for (const group of ctx.groups) {
    const looksStatic = looksStaticToCache(group.path);
    if (!looksStatic.static) continue;
    const entry = group.entries[0] as CaptureEntry;
    if (entry.response.status < 200 || entry.response.status >= 400) continue;

    const candidates = originCandidates(group.path).filter((c) => c.path !== group.path);
    const byPath = index.get(group.host) ?? new Map<string, Located>();
    const match = candidates.find((c) => byPath.has(c.path));
    const dynamicTwin = match === undefined ? undefined : byPath.get(match.path);

    const signalsHere = identitySignals(entry, group.entries, ctx.normalisers);
    const twinEntry = dynamicTwin === undefined ? undefined : (dynamicTwin.entries[0] as CaptureEntry);
    const signalsThere =
      twinEntry === undefined ? [] : identitySignals(twinEntry, dynamicTwin?.entries ?? [], ctx.normalisers);
    if (signalsHere.length === 0 && signalsThere.length === 0) continue;

    const sameBody =
      twinEntry !== undefined && ctx.normalisers.equivalent(entry.response.body, twinEntry.response.body);
    const store = storability(entry.request, entry.response);
    const hit = anyHit(entry);
    const kind = sameBody || hasProof(signalsHere) ? ('proof' as const) : ('inference' as const);

    out.push(
      makeFinding('CKL-D001', {
        resource: resourceLabel(entry),
        summary: `To a cache, ${group.path} ${looksStatic.why}. The origin served ${
          sameBody && twinEntry !== undefined
            ? `the same content as ${dynamicTwin?.path ?? 'a dynamic route'}`
            : 'a response that identifies a user'
        }. ${
          store.mayStore
            ? `A shared cache may store it (${store.reason}): an attacker who gets a victim to request this URL fixes the victim's own response at a key the attacker can then read.`
            : `As captured the response is not storable by a shared cache (${store.reason}), so the deception has no sink unless the directives differ at the edge.`
        }`,
        kind,
        confidence: kind === 'proof' ? 1 : 0.65,
        evidence: [
          ev('cache view', looksStatic.why),
          ...(match === undefined
            ? [
                ev(
                  'origin view',
                  'no sibling dynamic route for this path is present in the capture, so the resolution is inferred from the response content alone',
                ),
              ]
            : [
                ev(
                  'origin view',
                  `the path resolves to ${match.path} after [${match.via.join(', ')}], and the capture contains that resource`,
                ),
              ]),
          ...(sameBody && twinEntry !== undefined
            ? [
                ev(
                  'identical content',
                  `entry ${entry.index} and entry ${twinEntry.index} returned the same body once nonces and timestamps were normalised, which is what proves the origin resolved the suffixed path to the dynamic route`,
                ),
              ]
            : []),
          ev(
            'what identified the user',
            describeIdentity(signalsHere.length > 0 ? signalsHere : signalsThere),
          ),
          ev('storability', store.reason),
          ...(hit === null
            ? []
            : [ev('cache evidence', `${hit.header.name}: ${hit.header.value} (${hit.vendor}) — the response was served from a shared store`)]),
          ...(kind === 'inference'
            ? [
                ev(
                  'why this is an inference',
                  'the cache’s static-file rule is a configuration the capture cannot show; what the capture shows is that a static-looking path returned user-specific content',
                ),
              ]
            : []),
        ],
        entries: twinEntry === undefined ? [entry.index] : [entry.index, twinEntry.index],
      }),
    );
  }
  return out;
}

/** CKL-D002 — which delimiters the origin tolerated. */
export function delimiterTolerance(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const index = pathIndex(ctx);
  for (const group of ctx.groups) {
    const entry = group.entries[0] as CaptureEntry;
    if (entry.response.status < 200 || entry.response.status >= 400) continue;
    const byPath = index.get(group.host) ?? new Map<string, Located>();
    const tolerated: { token: string; label: string; why: string; base: string; proof: boolean; twin: number | null }[] = [];
    for (const split of delimiterSplits(group.path)) {
      const twin = byPath.get(split.base);
      if (twin === undefined) continue;
      const twinEntry = twin.entries[0] as CaptureEntry;
      if (twinEntry.index === entry.index) continue;
      const proof = ctx.normalisers.equivalent(entry.response.body, twinEntry.response.body);
      if (tolerated.some((t) => t.token === split.delimiter.token)) continue;
      tolerated.push({
        token: split.delimiter.token,
        label: split.delimiter.label,
        why: split.delimiter.why,
        base: split.base,
        proof,
        twin: twinEntry.index,
      });
    }
    if (tolerated.length === 0) continue;
    const anyProof = tolerated.some((t) => t.proof);
    const untested = DELIMITERS.filter((d) => !tolerated.some((t) => t.token === d.token)).map((d) => d.token);
    out.push(
      makeFinding('CKL-D002', {
        resource: resourceLabel(entry),
        summary: `The origin served a ${entry.response.status} for ${group.path}, which is ${tolerated
          .map((t) => `${t.base} plus the ${t.label} delimiter "${t.token}"`)
          .join(', and ')}. A delimiter the origin discards and the cache keys on is the mechanism every suffix-based deception needs.`,
        kind: anyProof ? 'proof' : 'inference',
        confidence: anyProof ? 1 : 0.6,
        evidence: [
          ...tolerated.map((t) =>
            ev(
              `delimiter "${t.token}" tolerated`,
              `${t.label}: ${t.why}. Base resource ${t.base} is entry ${t.twin ?? '?'}; the suffixed form returned ${
                t.proof ? 'an identical body once normalised' : 'a 2xx but a different body'
              }`,
            ),
          ),
          ev(
            'not shown tolerated by this capture',
            untested.length === 0
              ? 'every delimiter in the matrix was shown tolerated for this resource'
              : `the capture does not show the origin tolerating these: ${untested.join(' ')} — the delimiter matrix in \`plan\` covers them`,
          ),
        ],
        entries: [entry.index, ...tolerated.map((t) => t.twin).filter((n): n is number => n !== null)],
      }),
    );
  }
  return out;
}

/** CKL-D003 — a path that looks like it is under a static directory but is not. */
export function staticPrefixEscape(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const index = pathIndex(ctx);
  for (const group of ctx.groups) {
    const lower = group.path.toLowerCase();
    const prefix = STATIC_PREFIXES.find((p) => lower.startsWith(p));
    if (prefix === undefined) continue;
    const entry = group.entries[0] as CaptureEntry;
    if (entry.response.status < 200 || entry.response.status >= 400) continue;
    const escaped = originCandidates(group.path).filter(
      (c) => !c.path.toLowerCase().startsWith(prefix) && c.path !== group.path,
    );
    if (escaped.length === 0) continue;
    const byPath = index.get(group.host) ?? new Map<string, Located>();
    const match = escaped.find((c) => byPath.has(c.path));
    const twin = match === undefined ? undefined : byPath.get(match.path);
    const twinEntry = twin === undefined ? undefined : (twin.entries[0] as CaptureEntry);
    const signals = identitySignals(entry, group.entries, ctx.normalisers);
    if (match === undefined && signals.length === 0) continue;
    const sameBody =
      twinEntry !== undefined && ctx.normalisers.equivalent(entry.response.body, twinEntry.response.body);
    const store = storability(entry.request, entry.response);
    out.push(
      makeFinding('CKL-D003', {
        resource: resourceLabel(entry),
        summary: `${group.path} begins with ${prefix}, which a cache rule can match on the raw path, but it normalises out of that directory to ${
          match?.path ?? escaped.map((e) => e.path).join(', ')
        }. ${store.mayStore ? `A shared cache may store the response (${store.reason}).` : `The response is not storable as captured (${store.reason}).`}`,
        kind: sameBody || hasProof(signals) ? 'proof' : 'inference',
        confidence: sameBody || hasProof(signals) ? 1 : 0.6,
        evidence: [
          ev('cache view', `the raw path starts with ${prefix}, so a prefix-based static rule matches it`),
          ...escaped
            .slice(0, 4)
            .map((c) => ev('origin view', `normalises to ${c.path} after [${c.via.join(', ')}]`)),
          ...(twinEntry === undefined
            ? []
            : [ev('target resource in capture', `${twin?.path ?? ''} is entry ${twinEntry.index}`)]),
          ...(sameBody && twinEntry !== undefined
            ? [ev('identical content', `entries ${entry.index} and ${twinEntry.index} returned the same normalised body`)]
            : []),
          ev('what identified the user', describeIdentity(signals)),
          ev('storability', store.reason),
        ],
        entries: twinEntry === undefined ? [entry.index] : [entry.index, twinEntry.index],
      }),
    );
  }
  return out;
}

/** CKL-D004 — the finding that matters: user-specific content a shared cache may keep. */
export function cacheableUserSpecific(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  for (const group of ctx.groups) {
    for (const entry of group.entries) {
      const store = storability(entry.request, entry.response);
      if (!store.mayStore) continue;
      const signals = identitySignals(entry, group.entries, ctx.normalisers);
      if (signals.length === 0) continue;
      // A response that only "looks" personal because it carries a sign-out
      // link is weak on its own; require either a proof-strength signal or two
      // independent inference signals before claiming this.
      if (!hasProof(signals) && signals.length < 2) continue;
      const hit = anyHit(entry);
      out.push(
        makeFinding('CKL-D004', {
          resource: resourceLabel(entry),
          summary: `This response identifies a user and a shared cache is permitted to store it (${store.reason}). What identified the user: ${describeIdentity(signals)}.`,
          kind: hasProof(signals) ? 'proof' : 'inference',
          confidence: hasProof(signals) ? 1 : 0.6,
          evidence: [
            ...signals.map((s) => ev(s.label, `${s.detail} [${s.strength}]`)),
            ev('storability', store.reason),
            ...(store.requiresRevalidation
              ? [
                  ev(
                    'revalidation',
                    'the response requires revalidation before reuse, which narrows but does not close the window: the body is still stored, and a cache may serve it when the origin is unreachable',
                  ),
                ]
              : []),
            ...(hit === null
              ? []
              : [
                  ev(
                    'cache evidence',
                    `${hit.header.name}: ${hit.header.value} (${hit.vendor}) — this is not a theoretical risk, the response came out of a shared store`,
                  ),
                ]),
          ],
          entries: [entry.index],
        }),
      );
    }
  }
  return out;
}

/** CKL-D005 — two spellings of one path, one resource. */
export function pathNormalisationDisagreement(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const byCandidate = new Map<string, { group: string; entry: CaptureEntry; via: readonly string[] }[]>();
  for (const group of ctx.groups) {
    if (looksStaticToCache(group.path).static) continue;
    const entry = group.entries[0] as CaptureEntry;
    for (const cand of originCandidates(group.path)) {
      const key = `${group.host}${cand.path}`;
      const list = byCandidate.get(key);
      const item = { group: group.key, entry, via: cand.via };
      if (list === undefined) byCandidate.set(key, [item]);
      else list.push(item);
    }
  }
  const reported = new Set<string>();
  for (const [canonical, items] of byCandidate) {
    if (items.length < 2) continue;
    const distinct = [...new Map(items.map((i) => [i.group, i])).values()];
    if (distinct.length < 2) continue;
    const [a, b] = distinct as [typeof items[0], typeof items[0]];
    const pairKey = [a.group, b.group].sort().join('::');
    if (reported.has(pairKey)) continue;
    reported.add(pairKey);
    const same = ctx.normalisers.equivalent(a.entry.response.body, b.entry.response.body);
    const store = storability(a.entry.request, a.entry.response);
    out.push(
      makeFinding('CKL-D005', {
        resource: `${a.entry.request.method} ${a.group}`,
        summary: `${a.group} and ${b.group} both normalise to ${canonical}. A cache comparing raw bytes keys them separately while the origin treats them as one resource, which both splits the cache and hands an attacker a second key for the same content.`,
        kind: same ? 'proof' : 'inference',
        confidence: same ? 1 : 0.5,
        evidence: [
          ev('spelling A', `${a.group} via [${a.via.length === 0 ? 'no transformation' : a.via.join(', ')}] (entry ${a.entry.index})`),
          ev('spelling B', `${b.group} via [${b.via.length === 0 ? 'no transformation' : b.via.join(', ')}] (entry ${b.entry.index})`),
          ev(
            same ? 'identical content' : 'content differs',
            same
              ? 'both returned the same body once normalised, so the origin really does resolve them to one resource'
              : 'the bodies differ, so the shared normalisation is a model of plausible server behaviour rather than something the capture demonstrates',
          ),
          ev('storability', store.reason),
        ],
        entries: [a.entry.index, b.entry.index],
      }),
    );
  }
  return out;
}

export const DECEPTION_RULES = [
  staticSuffixDeception,
  delimiterTolerance,
  staticPrefixEscape,
  cacheableUserSpecific,
  pathNormalisationDisagreement,
] as const;

/** Exported for the key model: the parsed URL of a group's first entry. */
export function groupUrl(entry: CaptureEntry): string {
  const u = parseUrl(entry.request.url);
  return `${u.host}${u.path}`;
}
