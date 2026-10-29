/**
 * The analysis orchestrator: group the capture, infer a key per resource, run
 * every rule, and sort the result so the strongest evidence is read first.
 */

import { groupByResource } from './group.js';
import { inferKeys } from './key.js';
import { NormaliserSet } from './normalise.js';
import { Redactor } from './redact.js';
import { DECEPTION_RULES } from './rules/deception.js';
import { DIRECTIVE_RULES } from './rules/directives.js';
import { EVIDENCE_RULES, cacheHeaderTable } from './rules/evidence.js';
import { UNKEYED_RULES } from './rules/unkeyed.js';
import type { RuleContext } from './rules/util.js';
import { TOOL, VERSION } from './version.js';
import { SEVERITY_ORDER, type CaptureEntry, type Finding, type Report } from './types.js';

export interface AnalyseOptions {
  readonly normalisers?: NormaliserSet;
  /** Redact credential values in all output. Default true. */
  readonly redact?: boolean;
  readonly captureLabels?: readonly string[];
}

const ALL_RULES = [...UNKEYED_RULES, ...DECEPTION_RULES, ...DIRECTIVE_RULES, ...EVIDENCE_RULES];

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (bySeverity !== 0) return bySeverity;
    if (a.kind !== b.kind) return a.kind === 'proof' ? -1 : 1;
    if (a.confidence !== b.confidence) return b.confidence - a.confidence;
    if (a.ruleId !== b.ruleId) return a.ruleId.localeCompare(b.ruleId);
    return a.resource.localeCompare(b.resource);
  });
}

/**
 * Apply the redactor to every string in a finished report. Running this as a
 * final pass is what makes the redaction guarantee hold for every output
 * format and every rule, rather than depending on each rule remembering.
 */
export function redactReport(report: Report, redactor: Redactor): Report {
  if (!redactor.enabled) return report;
  return JSON.parse(JSON.stringify(report), (_key: string, value: unknown) =>
    typeof value === 'string' ? redactor.text(value) : value,
  ) as Report;
}

export function analyse(entries: readonly CaptureEntry[], options: AnalyseOptions = {}): Report {
  const normalisers = options.normalisers ?? NormaliserSet.default();
  const redact = options.redact ?? true;
  const redactor = Redactor.fromEntries(entries, redact);
  const groups = groupByResource(entries);
  const ctx: RuleContext = { entries, groups, normalisers, redactor };

  const findings: Finding[] = [];
  for (const rule of ALL_RULES) findings.push(...rule(ctx));

  const report: Report = {
    tool: TOOL,
    version: VERSION,
    captures: options.captureLabels ?? [...new Set(entries.map((e) => e.source))],
    entryCount: entries.length,
    redacted: redact,
    normalisers: normalisers.ids(),
    keys: inferKeys(groups, normalisers),
    findings: sortFindings(findings),
    cacheHeaders: cacheHeaderTable(ctx),
  };
  return redactReport(report, redactor);
}
