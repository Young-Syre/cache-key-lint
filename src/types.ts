/** Severity ladder, ordered most to least serious. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: readonly Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
] as const;

/**
 * Whether a finding is something the capture *shows* or something the tool
 * *deduces*. The distinction matters: a cache key is private to the cache, so
 * almost nothing about it can be proven from the outside. Anything labelled
 * `inference` carries a confidence and should be confirmed with the request
 * matrix that `plan` emits.
 */
export type FindingKind = 'proof' | 'inference';

export interface HeaderPair {
  /** Header name exactly as captured. Compare with `lower`. */
  readonly name: string;
  readonly lower: string;
  readonly value: string;
}

export interface CapturedRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: readonly HeaderPair[];
  /** Request body as captured; `null` when the capture recorded none. */
  readonly body: string | null;
}

export interface CapturedResponse {
  readonly status: number;
  readonly headers: readonly HeaderPair[];
  readonly body: string | null;
}

export interface CaptureEntry {
  /** 1-based position across all loaded captures, used to cite evidence. */
  readonly index: number;
  /** Capture label — the file's basename, never a filesystem path. */
  readonly source: string;
  readonly request: CapturedRequest;
  readonly response: CapturedResponse;
}

export interface Capture {
  readonly label: string;
  readonly format: 'har' | 'ckl';
  readonly entries: readonly CaptureEntry[];
}

export interface Evidence {
  readonly label: string;
  readonly detail: string;
}

export interface Finding {
  readonly ruleId: string;
  readonly rule: string;
  readonly severity: Severity;
  readonly kind: FindingKind;
  /** 0..1. Always 1 for `proof`. */
  readonly confidence: number;
  /** The resource the finding is about, as a method + URL or a path. */
  readonly resource: string;
  readonly summary: string;
  readonly evidence: readonly Evidence[];
  /** Entry indices this finding was derived from. */
  readonly entries: readonly number[];
}

export interface KeyComponent {
  readonly component: string;
  readonly evidence: string;
}

export interface InferredKey {
  readonly url: string;
  readonly methods: readonly string[];
  readonly observations: number;
  readonly inKey: readonly KeyComponent[];
  readonly notInKey: readonly KeyComponent[];
  readonly unknown: readonly KeyComponent[];
  readonly confidence: number;
  /** Human-readable list of what the confidence figure was built from. */
  readonly basis: readonly string[];
}

export interface CacheHeaderRow {
  readonly entry: number;
  readonly resource: string;
  readonly header: string;
  readonly value: string;
  readonly note: string;
}

export interface Report {
  readonly tool: string;
  readonly version: string;
  readonly captures: readonly string[];
  readonly entryCount: number;
  readonly redacted: boolean;
  readonly normalisers: readonly string[];
  readonly keys: readonly InferredKey[];
  readonly findings: readonly Finding[];
  readonly cacheHeaders: readonly CacheHeaderRow[];
}

export interface PlanProbe {
  readonly group: string;
  readonly method: string;
  readonly url: string;
  readonly headers: readonly HeaderPair[];
  readonly purpose: string;
  readonly expect: string;
}

export interface Plan {
  readonly tool: string;
  readonly version: string;
  readonly target: string;
  readonly buster: string;
  readonly warning: readonly string[];
  readonly probes: readonly PlanProbe[];
  readonly notesFromCapture: readonly string[];
}

export function severityAtLeast(value: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(value) <= SEVERITY_ORDER.indexOf(threshold);
}
