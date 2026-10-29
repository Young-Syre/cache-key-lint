import type { Redactor } from '../redact.js';
import type { NormaliserSet } from '../normalise.js';
import type { ResourceGroup } from '../group.js';
import type { CaptureEntry, Evidence, Finding, FindingKind, Severity } from '../types.js';
import { rule } from './catalogue.js';

export interface RuleContext {
  readonly entries: readonly CaptureEntry[];
  readonly groups: readonly ResourceGroup[];
  readonly normalisers: NormaliserSet;
  readonly redactor: Redactor;
}

export interface FindingDraft {
  readonly resource: string;
  readonly summary: string;
  readonly evidence: readonly Evidence[];
  readonly entries: readonly number[];
  readonly kind?: FindingKind;
  readonly confidence?: number;
  readonly severity?: Severity;
}

/**
 * Build a finding from the catalogue entry plus the draft. A `proof` always
 * carries confidence 1; an `inference` must state a confidence, defaulting to
 * a deliberately unflattering 0.5 when a rule does not supply one.
 */
export function makeFinding(id: string, draft: FindingDraft): Finding {
  const meta = rule(id);
  const kind = draft.kind ?? meta.defaultKind;
  const confidence = kind === 'proof' ? 1 : (draft.confidence ?? 0.5);
  return {
    ruleId: meta.id,
    rule: meta.name,
    severity: draft.severity ?? meta.severity,
    kind,
    confidence: Math.round(confidence * 100) / 100,
    resource: draft.resource,
    summary: draft.summary,
    evidence: draft.evidence,
    entries: [...draft.entries].sort((a, b) => a - b),
  };
}

export function ev(label: string, detail: string): Evidence {
  return { label, detail };
}

export function describeEntry(entry: CaptureEntry): string {
  return `entry ${entry.index} (${entry.request.method} ${entry.request.url} -> ${entry.response.status})`;
}

/** Short, stable resource label used as the finding's subject. */
export function resourceLabel(entry: CaptureEntry): string {
  return `${entry.request.method} ${entry.request.url}`;
}
