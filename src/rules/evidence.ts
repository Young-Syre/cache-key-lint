/**
 * Capture evidence.
 *
 * A cache-status header is the only thing in a capture that reports on the
 * cache's own behaviour rather than the origin's. These rules therefore carry
 * the highest severity in the tool, and they are pure proofs: the tool is
 * repeating what the serving cache said, not modelling anything.
 */

import { anyHit, cacheObservations } from '../group.js';
import { describeIdentity, hasProof, identitySignals } from '../identity.js';
import { ageSeconds, storability } from '../policy.js';
import type { CacheHeaderRow, Finding } from '../types.js';
import { ev, makeFinding, resourceLabel, type RuleContext } from './util.js';

/** CKL-E001 — a hit on something that should never have been stored. */
export function hitOnPrivateResponse(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  for (const group of ctx.groups) {
    for (const entry of group.entries) {
      const hit = anyHit(entry);
      if (hit === null) continue;
      const signals = identitySignals(entry, group.entries, ctx.normalisers);
      if (signals.length === 0) continue;
      const store = storability(entry.request, entry.response);
      out.push(
        makeFinding('CKL-E001', {
          resource: resourceLabel(entry),
          summary: `${hit.header.name}: ${hit.header.value} — the serving cache (${hit.vendor}) reports this response came from its store, and the response identifies a user. ${describeIdentity(signals)}.`,
          kind: 'proof',
          evidence: [
            ev('cache status', `${hit.header.name}: ${hit.header.value} (${hit.vendor})`),
            ...signals.map((s) => ev(s.label, `${s.detail} [${s.strength}]`)),
            ev('directives', store.reason),
            ev(
              'why this outranks everything else in the report',
              'the other rules argue from what the origin did and what the directives permit; this one is the cache stating that the response was stored and reused',
            ),
            ...(hasProof(signals)
              ? []
              : [
                  ev(
                    'caveat',
                    'the identity signals here are heuristic, so confirm the stored body is genuinely another user’s before reporting it as such',
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

/** CKL-E002 — a positive Age on a per-user response. */
export function agedUserResponse(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  for (const group of ctx.groups) {
    for (const entry of group.entries) {
      const age = ageSeconds(entry.response);
      if (age === null || age <= 0) continue;
      const signals = identitySignals(entry, group.entries, ctx.normalisers);
      if (signals.length === 0) continue;
      const store = storability(entry.request, entry.response);
      out.push(
        makeFinding('CKL-E002', {
          resource: resourceLabel(entry),
          summary: `Age: ${age} means a shared cache has held this response for ${age} seconds, and the response identifies a user. ${describeIdentity(signals)}.`,
          kind: 'proof',
          evidence: [
            ev('Age', String(age)),
            ...signals.map((s) => ev(s.label, `${s.detail} [${s.strength}]`)),
            ev('directives', store.reason),
          ],
          entries: [entry.index],
        }),
      );
    }
  }
  return out;
}

/** The cache-header evidence table printed with every report. */
export function cacheHeaderTable(ctx: RuleContext): CacheHeaderRow[] {
  const rows: CacheHeaderRow[] = [];
  for (const group of ctx.groups) {
    for (const entry of group.entries) {
      for (const obs of cacheObservations(entry)) {
        const signals = identitySignals(entry, group.entries, ctx.normalisers);
        const note = obs.hit
          ? signals.length > 0
            ? 'served from store, and this response identifies a user'
            : 'served from store'
          : 'reported by the serving cache; not a hit';
        rows.push({
          entry: entry.index,
          resource: resourceLabel(entry),
          header: obs.header.name,
          value: ctx.redactor.text(obs.header.value),
          note: `${obs.vendor} — ${note}`,
        });
      }
    }
  }
  return rows;
}

export const EVIDENCE_RULES = [hitOnPrivateResponse, agedUserResponse] as const;
