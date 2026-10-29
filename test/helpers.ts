import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { mergeCaptures, parseCapture } from '../src/capture.js';
import type { CaptureEntry, Finding, Report } from '../src/types.js';

/** Repo root, resolved from the compiled test's own location (dist/test). */
export const ROOT = new URL('../../', import.meta.url).pathname;
export const EXAMPLES = join(ROOT, 'examples');
export const SRC = join(ROOT, 'src');

export function exampleEntries(...names: string[]): CaptureEntry[] {
  const loaded = names.map((n) => parseCapture(readFileSync(join(EXAMPLES, n), 'utf8'), n));
  return mergeCaptures(loaded).entries;
}

export function ruleIdsIn(report: Report): string[] {
  return [...new Set(report.findings.map((f) => f.ruleId))].sort();
}

export function findingsFor(report: Report, ruleId: string): Finding[] {
  return report.findings.filter((f) => f.ruleId === ruleId);
}

/** Every .ts file under src/, recursively. */
export function sourceFiles(dir = SRC): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(full));
    else if (entry.name.endsWith('.ts')) out.push(full);
  }
  return out;
}
