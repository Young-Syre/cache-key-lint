/**
 * Output formatting: text for a terminal, markdown for a report, JSON for a
 * pipeline. The three are built from the same report object, so a finding can
 * never appear in one and not another.
 */

import { CACHE_STATUS_HEADERS } from './headers.js';
import { RULES } from './rules/catalogue.js';
import { DELIMITERS } from './url.js';
import { SEVERITY_ORDER, type Finding, type InferredKey, type Plan, type Report, type Severity } from './types.js';

export type Format = 'text' | 'json' | 'markdown';

export function severityCounts(findings: readonly Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity] += 1;
  return out;
}

function kindTag(f: Finding): string {
  return f.kind === 'proof' ? 'proof' : `inference ${f.confidence.toFixed(2)}`;
}

function keyLines(key: InferredKey, indent: string): string[] {
  const out: string[] = [];
  out.push(`${indent}${key.url}  [${key.methods.join(', ')}; ${key.observations} observation${key.observations === 1 ? '' : 's'}; key confidence ${key.confidence.toFixed(2)}]`);
  const section = (title: string, items: readonly { component: string; evidence: string }[]): void => {
    if (items.length === 0) return;
    out.push(`${indent}  ${title}`);
    for (const item of items) {
      const wrapped = wrap(`${item.component} — ${item.evidence}`, 86);
      wrapped.forEach((l, i) => out.push(`${indent}    ${i === 0 ? '' : '  '}${l}`));
    }
  };
  section('in the key:', key.inKey);
  section('not in the key:', key.notInKey);
  section('untested by this capture:', key.unknown);
  for (const [i, l] of wrap(`confidence from: ${key.basis.join('; ')}`, 86).entries()) {
    out.push(`${indent}  ${i === 0 ? '' : '  '}${l}`);
  }
  return out;
}

export function formatReportText(report: Report): string {
  const lines: string[] = [];
  lines.push(
    ...wrap(
      `${report.tool} ${report.version} — ${report.entryCount} entr${report.entryCount === 1 ? 'y' : 'ies'} from ${report.captures.join(', ')}`,
      96,
    ),
  );
  lines.push(
    report.redacted
      ? 'Credential values are redacted.'
      : 'REDACTION DISABLED: credential values are printed verbatim below.',
  );
  lines.push('');
  lines.push('INFERRED CACHE KEYS');
  if (report.keys.length === 0) lines.push('  (none)');
  for (const key of report.keys) {
    lines.push(...keyLines(key, '  '));
    lines.push('');
  }

  lines.push('CACHE HEADER EVIDENCE');
  if (report.cacheHeaders.length === 0) {
    lines.push('  no cache-status headers in the capture — every verdict below rests on the directive model alone');
  } else {
    for (const row of report.cacheHeaders) {
      lines.push(`  entry ${row.entry}  ${row.header}: ${row.value}`);
      for (const l of wrap(row.resource, 88)) lines.push(`    ${l}`);
      for (const l of wrap(row.note, 88)) lines.push(`    ${l}`);
    }
  }
  lines.push('');

  lines.push(`FINDINGS (${report.findings.length})`);
  if (report.findings.length === 0) lines.push('  none');
  for (const f of report.findings) {
    lines.push('');
    lines.push(`  [${f.severity}] ${f.ruleId} (${kindTag(f)}) — ${f.rule}`);
    lines.push(`    resource: ${f.resource}`);
    lines.push(`    entries:  ${f.entries.join(', ')}`);
    for (const line of wrap(f.summary, 92)) lines.push(`    ${line}`);
    for (const e of f.evidence) {
      const body = wrap(`${e.label}: ${e.detail}`, 88);
      body.forEach((l, i) => lines.push(`      ${i === 0 ? '- ' : '  '}${l}`));
    }
  }

  lines.push('');
  const counts = severityCounts(report.findings);
  lines.push(
    `SUMMARY  ${SEVERITY_ORDER.map((s) => `${s} ${counts[s]}`).join('  ')}  |  proofs ${report.findings.filter((f) => f.kind === 'proof').length}, inferences ${report.findings.filter((f) => f.kind === 'inference').length}`,
  );
  lines.push(...wrap(`Body normalisers applied before comparison: ${report.normalisers.join(', ')}`, 92));
  return lines.join('\n');
}

export function formatReportMarkdown(report: Report): string {
  const lines: string[] = [];
  lines.push(`# ${report.tool} report`);
  lines.push('');
  lines.push(
    `${report.entryCount} entr${report.entryCount === 1 ? 'y' : 'ies'} from \`${report.captures.join('`, `')}\`. ${report.redacted ? 'Credential values are redacted.' : '**Redaction is disabled in this report.**'}`,
  );
  lines.push('');
  lines.push('## Inferred cache keys');
  lines.push('');
  for (const key of report.keys) {
    lines.push(`### \`${key.url}\``);
    lines.push('');
    lines.push(`Methods: ${key.methods.join(', ')} · observations: ${key.observations} · **key confidence ${key.confidence.toFixed(2)}**`);
    lines.push('');
    lines.push('| placement | component | evidence |');
    lines.push('| --- | --- | --- |');
    for (const c of key.inKey) lines.push(`| in key | \`${c.component}\` | ${c.evidence} |`);
    for (const c of key.notInKey) lines.push(`| **not in key** | \`${c.component}\` | ${c.evidence} |`);
    for (const c of key.unknown) lines.push(`| untested | \`${c.component}\` | ${c.evidence} |`);
    lines.push('');
    lines.push(`Confidence from: ${key.basis.join('; ')}.`);
    lines.push('');
  }

  lines.push('## Cache header evidence');
  lines.push('');
  if (report.cacheHeaders.length === 0) {
    lines.push('No cache-status headers were present in the capture, so no finding in this report rests on observed cache behaviour.');
  } else {
    lines.push('| entry | resource | header | value | note |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const r of report.cacheHeaders) {
      lines.push(`| ${r.entry} | \`${r.resource}\` | \`${r.header}\` | \`${r.value}\` | ${r.note} |`);
    }
  }
  lines.push('');

  lines.push(`## Findings (${report.findings.length})`);
  lines.push('');
  if (report.findings.length === 0) lines.push('None.');
  for (const f of report.findings) {
    lines.push(`### ${f.ruleId} — ${f.rule}`);
    lines.push('');
    lines.push(`**${f.severity}** · ${kindTag(f)} · \`${f.resource}\` · entries ${f.entries.join(', ')}`);
    lines.push('');
    lines.push(f.summary);
    lines.push('');
    for (const e of f.evidence) lines.push(`- **${e.label}** — ${e.detail}`);
    lines.push('');
  }

  const counts = severityCounts(report.findings);
  lines.push('## Summary');
  lines.push('');
  lines.push(`| ${SEVERITY_ORDER.join(' | ')} |`);
  lines.push(`| ${SEVERITY_ORDER.map(() => '---').join(' | ')} |`);
  lines.push(`| ${SEVERITY_ORDER.map((s) => counts[s]).join(' | ')} |`);
  lines.push('');
  lines.push(
    `Proofs: ${report.findings.filter((f) => f.kind === 'proof').length}. Inferences: ${report.findings.filter((f) => f.kind === 'inference').length}.`,
  );
  lines.push('');
  lines.push(`Body normalisers applied before comparison: ${report.normalisers.map((n) => `\`${n}\``).join(', ')}.`);
  return lines.join('\n');
}

export function formatReport(report: Report, format: Format): string {
  if (format === 'json') return JSON.stringify(report, null, 2);
  if (format === 'markdown') return formatReportMarkdown(report);
  return formatReportText(report);
}

export function formatPlanText(plan: Plan): string {
  const lines: string[] = [];
  lines.push(`${plan.tool} ${plan.version} — request matrix for ${plan.target}`);
  lines.push('');
  lines.push('!! CACHE-BUSTER DISCIPLINE — READ BEFORE SENDING ANYTHING');
  for (const w of plan.warning) for (const l of wrap(w, 90)) lines.push(`   ${l}`);
  lines.push('');
  if (plan.notesFromCapture.length > 0) {
    lines.push('FROM THE CAPTURE');
    for (const n of plan.notesFromCapture) for (const l of wrap(n, 90)) lines.push(`   ${l}`);
    lines.push('');
  }
  lines.push(`PROBES (${plan.probes.length})  buster: ${plan.buster}`);
  let group = '';
  for (const [i, probe] of plan.probes.entries()) {
    if (probe.group !== group) {
      group = probe.group;
      lines.push('');
      lines.push(`-- ${group} --`);
    }
    lines.push('');
    lines.push(`  ${String(i + 1).padStart(3, '0')}  ${probe.method} ${probe.url}`);
    for (const h of probe.headers) lines.push(`       ${h.name}: ${h.value}`);
    for (const l of wrap(`why: ${probe.purpose}`, 86)) lines.push(`       ${l}`);
    for (const l of wrap(`look for: ${probe.expect}`, 86)) lines.push(`       ${l}`);
  }
  return lines.join('\n');
}

export function formatPlanMarkdown(plan: Plan): string {
  const lines: string[] = [];
  lines.push(`# Request matrix — \`${plan.target}\``);
  lines.push('');
  lines.push('> **Cache-buster discipline — read before sending anything.**');
  for (const w of plan.warning) lines.push(`> ${w}`);
  lines.push('');
  if (plan.notesFromCapture.length > 0) {
    lines.push('## From the capture');
    lines.push('');
    for (const n of plan.notesFromCapture) lines.push(`- ${n}`);
    lines.push('');
  }
  lines.push(`## Probes (${plan.probes.length})`);
  lines.push('');
  lines.push(`Buster: \`${plan.buster}\`.`);
  lines.push('');
  let group = '';
  for (const [i, probe] of plan.probes.entries()) {
    if (probe.group !== group) {
      group = probe.group;
      lines.push(`### ${group}`);
      lines.push('');
    }
    lines.push(`**${String(i + 1).padStart(3, '0')}** \`${probe.method} ${probe.url}\``);
    lines.push('');
    for (const h of probe.headers) lines.push(`- header \`${h.name}: ${h.value}\``);
    lines.push(`- why: ${probe.purpose}`);
    lines.push(`- look for: ${probe.expect}`);
    lines.push('');
  }
  return lines.join('\n');
}

export function formatPlan(plan: Plan, format: Format): string {
  if (format === 'json') return JSON.stringify(plan, null, 2);
  if (format === 'markdown') return formatPlanMarkdown(plan);
  return formatPlanText(plan);
}

export function formatRules(format: Format): string {
  if (format === 'json') return JSON.stringify(RULES, null, 2);
  if (format === 'markdown') {
    const lines = ['| ID | name | severity | default kind | mechanism |', '| --- | --- | --- | --- | --- |'];
    for (const r of RULES) {
      lines.push(`| \`${r.id}\` | ${r.name} | ${r.severity} | ${r.defaultKind} | ${r.mechanism} |`);
    }
    return lines.join('\n');
  }
  const lines: string[] = [`${RULES.length} rules`, ''];
  for (const r of RULES) {
    lines.push(`${r.id}  [${r.severity}] (${r.defaultKind})  ${r.name}`);
    for (const l of wrap(r.mechanism, 88)) lines.push(`    ${l}`);
    lines.push('');
  }
  return lines.join('\n').trimEnd();
}

export function formatDelimiters(format: Format): string {
  if (format === 'json') return JSON.stringify(DELIMITERS, null, 2);
  if (format === 'markdown') {
    const lines = ['| delimiter | name | what has to be true at the origin |', '| --- | --- | --- |'];
    for (const d of DELIMITERS) lines.push(`| \`${d.token}\` | ${d.label} | ${d.why} |`);
    return lines.join('\n');
  }
  const out: string[] = [];
  for (const d of DELIMITERS) {
    out.push(`${d.token.padEnd(8)}${d.label}`);
    for (const l of wrap(d.why, 84)) out.push(`        ${l}`);
    out.push('');
  }
  return out.join('\n').trimEnd();
}

export function formatCacheHeaders(format: Format): string {
  if (format === 'json') return JSON.stringify(CACHE_STATUS_HEADERS, null, 2);
  if (format === 'markdown') {
    const lines = ['| header | reported by | values read as a hit |', '| --- | --- | --- |'];
    for (const h of CACHE_STATUS_HEADERS) {
      const hit =
        h.name.toLowerCase() === 'age' || h.name.toLowerCase() === 'x-cache-hits'
          ? 'any value greater than zero'
          : h.hit.length === 0
            ? 'none — reported as context only'
            : h.hit.map((v) => `\`${v}\``).join(', ');
      lines.push(`| \`${h.name}\` | ${h.vendor} | ${hit} |`);
    }
    return lines.join('\n');
  }
  return CACHE_STATUS_HEADERS.map(
    (h) => `${h.name.padEnd(24)}${h.vendor}${h.hit.length === 0 ? '' : `  [hit: ${h.hit.join(', ')}]`}`,
  ).join('\n');
}

export function formatNormalisers(ids: readonly { id: string; description: string }[], format: Format): string {
  if (format === 'json') return JSON.stringify(ids, null, 2);
  if (format === 'markdown') {
    const lines = ['| normaliser | what it masks |', '| --- | --- |'];
    for (const n of ids) lines.push(`| \`${n.id}\` | ${n.description} |`);
    return lines.join('\n');
  }
  return ids.map((n) => `${n.id.padEnd(24)}${n.description}`).join('\n');
}

function wrap(text: string, width: number): string[] {
  const words = text.split(/\s+/).filter((w) => w !== '');
  const out: string[] = [];
  let line = '';
  for (const word of words) {
    if (line === '') {
      line = word;
      continue;
    }
    if (line.length + 1 + word.length > width) {
      out.push(line);
      line = word;
      continue;
    }
    line = `${line} ${word}`;
  }
  if (line !== '') out.push(line);
  return out.length === 0 ? [''] : out;
}
