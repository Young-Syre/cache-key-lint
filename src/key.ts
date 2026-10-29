/**
 * The inferred cache key.
 *
 * This is the tool's main output and the thing the findings hang off. A cache
 * key is private to the cache, so almost nothing here can be proven from
 * outside — what the capture gives is a set of components the response
 * demonstrably depends on, a set the origin declares via Vary, and, when a
 * cache-status header is present, a small amount of real evidence about which
 * side of the line a component falls on.
 *
 * The confidence figure is deliberately mechanical, and the formula is in the
 * README so that a reader can judge it rather than trust it.
 */

import { CACHE_STATUS_LOWER, parseVary } from './headers.js';
import { cacheObservations, pairs, requestDelta, responseDelta, type ResourceGroup } from './group.js';
import type { NormaliserSet } from './normalise.js';
import type { CaptureEntry, InferredKey, KeyComponent } from './types.js';
import { parseUrl } from './url.js';

const BASE_CONFIDENCE = 0.3;
const CACHE_EVIDENCE_BONUS = 0.25;
const PER_PAIR_BONUS = 0.1;
const PER_PAIR_CAP = 0.3;
const VARY_BONUS = 0.1;
const UNATTRIBUTABLE_PENALTY = 0.1;
const MIN_CONFIDENCE = 0.1;
const MAX_CONFIDENCE = 0.95;

function add(list: KeyComponent[], component: string, evidence: string): void {
  if (list.some((c) => c.component === component)) return;
  list.push({ component, evidence });
}

export function inferKey(group: ResourceGroup, normalisers: NormaliserSet): InferredKey {
  const inKey: KeyComponent[] = [];
  const notInKey: KeyComponent[] = [];
  const unknown: KeyComponent[] = [];
  const basis: string[] = [];

  add(inKey, 'host', 'assumed: every cache in common use keys on the request host');
  add(inKey, 'path', 'assumed: every cache in common use keys on the request path');

  const methods = [...new Set(group.entries.map((e) => e.request.method))].sort();
  if (methods.length > 1) {
    add(unknown, 'method', `the capture contains ${methods.join(' and ')} for this resource, and nothing in it shows whether the method is part of the key`);
  } else {
    add(unknown, 'method', 'only one method was observed, so the method’s place in the key is untested');
  }

  const varyTokens = new Set<string>();
  let anyVary = false;
  for (const entry of group.entries) {
    const tokens = parseVary(entry.response.headers);
    if (tokens.length > 0) anyVary = true;
    for (const t of tokens) varyTokens.add(t);
  }
  for (const token of varyTokens) {
    if (token === '*') {
      add(notInKey, 'any stored response', 'Vary: * means no stored response can be selected for any request');
      continue;
    }
    add(inKey, `header:${token}`, `the origin declares Vary: ${token}, which a conformant cache must include in the key`);
  }
  if (anyVary) basis.push(`a Vary header was present (+${VARY_BONUS.toFixed(2)})`);

  const hasCacheEvidence = group.entries.some((e) =>
    e.response.headers.some((h) => CACHE_STATUS_LOWER.includes(h.lower)),
  );
  if (hasCacheEvidence) {
    basis.push(`a cache-status header was present on at least one observation (+${CACHE_EVIDENCE_BONUS.toFixed(2)})`);
  }

  let attributed = 0;
  let unattributable = 0;
  for (const [a, b] of pairs(group.entries)) {
    const delta = requestDelta(a, b);
    if (delta.dimensions === 0) continue;
    if (delta.dimensions > 1) {
      unattributable += 1;
      continue;
    }
    attributed += 1;
    const rdelta = responseDelta(a, b, normalisers);
    const earlier = a.index < b.index ? a : b;
    const later = a.index < b.index ? b : a;
    const laterHit = cacheObservations(later).some((o) => o.hit);
    const earlierHit = cacheObservations(earlier).some((o) => o.hit);

    const components = componentNames(delta);
    for (const component of components) {
      if (varyTokens.has(component.replace(/^header:/, ''))) continue;
      if (rdelta.varied) {
        if (laterHit && earlierHit) {
          add(inKey, component, `two observations differing only in ${component} both came from the cache store with different bodies, so the cache kept them apart`);
        } else {
          add(
            notInKey,
            component,
            `the response varied with ${component} and no Vary names it — inferred, not proven: the capture shows the origin reading it, not the cache ignoring it`,
          );
        }
        continue;
      }
      if (laterHit && !earlierHit) {
        add(
          notInKey,
          component,
          `changing ${component} produced an equivalent body served from the cache store (${describeHit(later)}), so the two requests shared one key`,
        );
        continue;
      }
      add(unknown, component, `changing ${component} did not change the response, so the capture cannot place it on either side of the key`);
    }
  }
  if (attributed > 0) {
    basis.push(
      `${attributed} single-variable pair${attributed === 1 ? '' : 's'} attributed (+${Math.min(attributed * PER_PAIR_BONUS, PER_PAIR_CAP).toFixed(2)})`,
    );
  }
  if (unattributable > 0) {
    basis.push(
      `${unattributable} pair${unattributable === 1 ? '' : 's'} differed in more than one request component and were ignored (-${UNATTRIBUTABLE_PENALTY.toFixed(2)})`,
    );
  }

  // Query parameters observed but never isolated.
  const seenParams = new Set<string>();
  for (const entry of group.entries) {
    for (const p of parseUrl(entry.request.url).params) seenParams.add(p.name);
  }
  for (const name of seenParams) {
    const component = `query:${name}`;
    if (inKey.some((c) => c.component === component) || notInKey.some((c) => c.component === component)) continue;
    add(unknown, component, 'the parameter appears in the capture but was never varied on its own, so its treatment is untested');
  }

  let confidence =
    BASE_CONFIDENCE +
    (hasCacheEvidence ? CACHE_EVIDENCE_BONUS : 0) +
    Math.min(attributed * PER_PAIR_BONUS, PER_PAIR_CAP) +
    (anyVary ? VARY_BONUS : 0) -
    (unattributable > 0 ? UNATTRIBUTABLE_PENALTY : 0);
  confidence = Math.max(MIN_CONFIDENCE, Math.min(MAX_CONFIDENCE, confidence));
  basis.unshift(`base ${BASE_CONFIDENCE.toFixed(2)}`);

  return {
    url: group.key,
    methods,
    observations: group.entries.length,
    inKey,
    notInKey,
    unknown,
    confidence: Math.round(confidence * 100) / 100,
    basis,
  };
}

function describeHit(entry: CaptureEntry): string {
  const hit = cacheObservations(entry).find((o) => o.hit);
  return hit === undefined ? 'cache hit' : `${hit.header.name}: ${hit.header.value}`;
}

function componentNames(delta: ReturnType<typeof requestDelta>): string[] {
  const out: string[] = [];
  for (const h of delta.headers) out.push(`header:${h}`);
  for (const c of delta.cookies) out.push(`cookie:${c}`);
  for (const q of delta.queryValues) out.push(`query:${q.name}`);
  if (delta.querySpelling.length > 0) out.push(`query-spelling:${delta.querySpelling.join('+')}`);
  if (delta.methodDiffers) out.push('method');
  if (delta.bodyDiffers) out.push('request-body');
  return out;
}

export function inferKeys(groups: readonly ResourceGroup[], normalisers: NormaliserSet): InferredKey[] {
  return groups.map((g) => inferKey(g, normalisers));
}
