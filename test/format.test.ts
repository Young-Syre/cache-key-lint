import assert from 'node:assert/strict';
import test from 'node:test';

import { analyse } from '../src/analyse.js';
import { formatReport, formatReportMarkdown, formatReportText, severityCounts } from '../src/format.js';
import { exampleEntries } from './helpers.js';

const report = analyse(exampleEntries('css-suffix-deception.har'));

test('the text report has the three documented sections and a summary line', () => {
  const text = formatReportText(report);
  assert.match(text, /^cache-key-lint \d+\.\d+\.\d+ — 4 entries/);
  assert.match(text, /^Credential values are redacted\.$/m);
  assert.match(text, /INFERRED CACHE KEYS/);
  assert.match(text, /CACHE HEADER EVIDENCE/);
  assert.match(text, /FINDINGS \(\d+\)/);
  assert.match(text, /SUMMARY {2}critical \d+ {2}high \d+/);
  assert.match(text, /Body normalisers applied before comparison:/);
});

test('the inferred key is printed before the findings, because the findings hang off it', () => {
  const text = formatReportText(report);
  assert.ok(text.indexOf('INFERRED CACHE KEYS') < text.indexOf('FINDINGS ('));
});

test('every key section states its confidence and the basis for it', () => {
  const text = formatReportText(report);
  for (const key of report.keys) {
    assert.ok(text.includes(`key confidence ${key.confidence.toFixed(2)}`));
  }
  assert.match(text, /confidence from: base 0\.30/);
});

test('each finding line carries severity, rule id and proof-or-inference', () => {
  const text = formatReportText(report);
  for (const f of report.findings) {
    const tag = f.kind === 'proof' ? '(proof)' : `(inference ${f.confidence.toFixed(2)})`;
    assert.ok(text.includes(`[${f.severity}] ${f.ruleId} ${tag}`), `missing header line for ${f.ruleId}`);
  }
});

test('the markdown report renders the key table and a severity table', () => {
  const md = formatReportMarkdown(report);
  assert.match(md, /\| placement \| component \| evidence \|/);
  assert.match(md, /\| critical \| high \| medium \| low \| info \|/);
  assert.match(md, /\*\*not in key\*\*|\| in key \|/);
});

test('a report with no cache headers says so explicitly in both renderings', () => {
  const bare = analyse(
    exampleEntries('unkeyed-query-cookie-and-directives.json').filter(
      (e) => !e.response.headers.some((h) => ['x-cache', 'age', 'x-vercel-cache'].includes(h.lower)),
    ),
  );
  assert.equal(bare.cacheHeaders.length, 0);
  assert.match(formatReportText(bare), /no cache-status headers in the capture/);
  assert.match(formatReportMarkdown(bare), /No cache-status headers were present/);
});

test('severityCounts totals the findings', () => {
  const counts = severityCounts(report.findings);
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  assert.equal(total, report.findings.length);
  assert.ok(counts.critical >= 1);
});

test('the json rendering is stable and complete', () => {
  const json = JSON.parse(formatReport(report, 'json')) as typeof report;
  assert.deepEqual(json.findings.map((f) => f.ruleId), report.findings.map((f) => f.ruleId));
  assert.deepEqual(json.keys.map((k) => k.url), report.keys.map((k) => k.url));
});

test('an unknown format falls back to text rather than throwing', () => {
  assert.equal(formatReport(report, 'text' as never), formatReportText(report));
});

test('long summaries are wrapped rather than emitted as one line', () => {
  for (const line of formatReportText(report).split('\n')) {
    assert.ok(line.length < 200, `unwrapped line of ${line.length} characters`);
  }
});
