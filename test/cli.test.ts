import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, parseArgs, run } from '../src/cli.js';
import { RULES } from '../src/rules/catalogue.js';
import { EXAMPLES, ROOT } from './helpers.js';

interface Captured {
  readonly code: number;
  readonly out: string;
  readonly err: string;
}

function cli(...argv: string[]): Captured {
  const out: string[] = [];
  const err: string[] = [];
  const code = run(argv, { out: (t) => out.push(t), err: (t) => err.push(t) });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

const ex = (name: string): string => join(EXAMPLES, name);

test('--help documents the commands, options and exit codes', () => {
  const r = cli('--help');
  assert.equal(r.code, EXIT_OK);
  for (const needle of ['USAGE', 'COMMANDS', 'OPTIONS', 'EXIT CODES', 'NETWORK', '--format', '--fail-on', '--no-redact', 'plan', 'rules', 'normalisers']) {
    assert.ok(r.out.includes(needle), `--help does not mention ${needle}`);
  }
});

test('-h and --help are equivalent, and --version prints just the version', () => {
  assert.equal(cli('-h').out, cli('--help').out);
  const v = cli('--version');
  assert.match(v.out, /^\d+\.\d+\.\d+$/);
  assert.equal(cli('-V').out, v.out);
});

test('the poisonable capture is reported and exits 1', () => {
  const r = cli(ex('unkeyed-x-forwarded-host.json'));
  assert.equal(r.code, EXIT_FINDINGS);
  assert.match(r.out, /CKL-U001/);
  assert.match(r.out, /CKL-U002/);
  assert.match(r.out, /INFERRED CACHE KEYS/);
});

test('the deception capture is reported and exits 1', () => {
  const r = cli(ex('css-suffix-deception.har'));
  assert.equal(r.code, EXIT_FINDINGS);
  assert.match(r.out, /CKL-D001/);
  assert.match(r.out, /CKL-D004/);
  assert.match(r.out, /CKL-E001/);
});

test('the well-configured capture comes back clean and exits 0', () => {
  const r = cli(ex('clean-well-configured.json'));
  assert.equal(r.code, EXIT_OK);
  assert.match(r.out, /FINDINGS \(0\)/);
});

test('the nonce-only capture reports nothing and exits 0', () => {
  const r = cli(ex('nonce-noise.json'));
  assert.equal(r.code, EXIT_OK);
  assert.match(r.out, /FINDINGS \(0\)/);
});

test('several captures can be analysed together', () => {
  const r = cli(ex('clean-well-configured.json'), ex('nonce-noise.json'));
  assert.equal(r.code, EXIT_OK);
  assert.match(r.out, /7 entries from clean-well-configured, nonce-noise/);
});

test('--fail-on controls the exit code without changing the report', () => {
  const low = cli(ex('unkeyed-query-cookie-and-directives.json'), '--fail-on', 'low');
  const critical = cli(ex('unkeyed-query-cookie-and-directives.json'), '--fail-on', 'critical');
  const never = cli(ex('unkeyed-query-cookie-and-directives.json'), '--fail-on', 'never');
  assert.equal(low.code, EXIT_FINDINGS);
  assert.equal(critical.code, EXIT_OK, 'that capture has no critical finding');
  assert.equal(never.code, EXIT_OK);
  assert.equal(low.out, critical.out);
  assert.equal(low.out, never.out);
});

test('--fail-on critical does trip on a capture with a critical finding', () => {
  assert.equal(cli(ex('css-suffix-deception.har'), '--fail-on', 'critical').code, EXIT_FINDINGS);
});

test('--format json emits a parseable report with the documented shape', () => {
  const r = cli(ex('css-suffix-deception.har'), '--format', 'json');
  const report = JSON.parse(r.out) as Record<string, unknown>;
  for (const field of ['tool', 'version', 'captures', 'entryCount', 'redacted', 'normalisers', 'keys', 'findings', 'cacheHeaders']) {
    assert.ok(field in report, `json report has no ${field}`);
  }
  assert.equal(report['tool'], 'cache-key-lint');
  assert.ok(Array.isArray(report['findings']));
});

test('--format markdown emits tables and the same findings as text', () => {
  const md = cli(ex('css-suffix-deception.har'), '--format', 'markdown').out;
  const json = JSON.parse(cli(ex('css-suffix-deception.har'), '--format', 'json').out) as {
    findings: { ruleId: string }[];
  };
  assert.match(md, /^# cache-key-lint report/m);
  assert.match(md, /\| placement \| component \| evidence \|/);
  assert.match(md, /## Cache header evidence/);
  for (const f of json.findings) assert.ok(md.includes(f.ruleId));
});

test('rules prints every catalogued rule in all three formats', () => {
  const text = cli('rules').out;
  for (const r of RULES) assert.ok(text.includes(r.id), `rules text omits ${r.id}`);
  const md = cli('rules', '--format', 'markdown').out;
  assert.match(md, /^\| ID \| name \| severity \| default kind \| mechanism \|/m);
  for (const r of RULES) assert.ok(md.includes(r.id));
  const json = JSON.parse(cli('rules', '--format', 'json').out) as unknown[];
  assert.equal(json.length, RULES.length);
});

test('normalisers prints the applied set', () => {
  const text = cli('normalisers').out;
  assert.match(text, /csp-nonce/);
  assert.match(text, /whitespace/);
  assert.equal(cli('normalisers', '--no-default-normalisers').out, '');
});

test('--normalisers adds rules from a file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ckl-test-'));
  const file = join(dir, 'extra.json');
  writeFileSync(file, JSON.stringify({ normalisers: [{ id: 'order-no', pattern: 'ORD-\\d+' }] }));
  assert.match(cli('normalisers', '--normalisers', file).out, /order-no/);
});

test('an unreadable or malformed capture is a usage error, not a crash', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ckl-test-'));
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, '{ not json');
  const missing = cli(join(dir, 'nope.json'));
  assert.equal(missing.code, EXIT_USAGE);
  assert.match(missing.err, /cannot read nope\.json/);
  const malformed = cli(bad);
  assert.equal(malformed.code, EXIT_USAGE);
  assert.match(malformed.err, /not valid JSON/);
});

test('no capture, an unknown flag and a missing flag value are usage errors', () => {
  assert.equal(cli().code, EXIT_USAGE);
  assert.match(cli().err, /no capture file given/);
  assert.equal(cli('--nope').code, EXIT_USAGE);
  assert.match(cli('--nope').err, /unknown option/);
  assert.equal(cli('--format').code, EXIT_USAGE);
  assert.match(cli('--format').err, /requires a value/);
  assert.equal(cli('--format', 'yaml').code, EXIT_USAGE);
  assert.match(cli('--format', 'yaml').err, /must be one of/);
  assert.equal(cli('--fail-on', 'urgent').code, EXIT_USAGE);
});

test('plan requires --url', () => {
  const r = cli('plan', ex('clean-well-configured.json'));
  assert.equal(r.code, EXIT_USAGE);
  assert.match(r.err, /plan requires --url/);
});

test('plan emits the matrix and exits 0 even for a URL not in the capture', () => {
  const r = cli('plan', ex('clean-well-configured.json'), '--url', 'https://www.example/account');
  assert.equal(r.code, EXIT_OK);
  assert.match(r.out, /CACHE-BUSTER DISCIPLINE/);
  assert.match(r.out, /cklcb=ckl001/);
});

test('plan works without a capture file', () => {
  const r = cli('plan', '--url', 'https://www.example/account');
  assert.equal(r.code, EXIT_OK);
  assert.match(r.out, /PROBES \(/);
});

test('-o writes the report to a file and says so on stderr', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ckl-test-'));
  const file = join(dir, 'report.md');
  const r = cli(ex('css-suffix-deception.har'), '--format', 'markdown', '-o', file);
  assert.equal(r.code, EXIT_FINDINGS);
  assert.equal(r.out, '');
  assert.match(r.err, /written to report\.md/);
  assert.match(readFileSync(file, 'utf8'), /# cache-key-lint report/);
});

test('--quiet suppresses capture parse warnings', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ckl-test-'));
  const file = join(dir, 'warn.json');
  writeFileSync(
    file,
    JSON.stringify({ entries: [{ request: {}, response: { status: 200 } }, { request: { url: '/a' }, response: { status: 200 } }] }),
  );
  assert.match(cli(file).err, /warning:/);
  assert.equal(cli(file, '--quiet').err, '');
});

test('the lint subcommand name is accepted explicitly', () => {
  assert.equal(cli('lint', ex('clean-well-configured.json')).out, cli(ex('clean-well-configured.json')).out);
});

test('parseArgs defaults are the documented ones', () => {
  const args = parseArgs(['a.har']);
  assert.equal(args.command, 'lint');
  assert.equal(args.format, 'text');
  assert.equal(args.failOn, 'medium');
  assert.equal(args.redact, true);
  assert.equal(args.useDefaults, true);
  assert.equal(args.out, null);
  assert.deepEqual(args.files, ['a.har']);
});

test('the installed binary runs end to end and returns the documented exit codes', () => {
  const bin = join(ROOT, 'dist/src/cli.js');
  const clean = execFileSync(process.execPath, [bin, ex('clean-well-configured.json')], { encoding: 'utf8' });
  assert.match(clean, /FINDINGS \(0\)/);
  let code = 0;
  try {
    execFileSync(process.execPath, [bin, ex('css-suffix-deception.har')], { encoding: 'utf8', stdio: 'pipe' });
  } catch (err) {
    code = (err as { status: number }).status;
  }
  assert.equal(code, EXIT_FINDINGS);
});

test('delimiters prints the full matrix in every format', () => {
  const text = cli('delimiters').out;
  for (const token of ['.', '/', '%2F', '//', ';', '%3B', '?', '%23', '..%2f']) {
    assert.ok(text.includes(token), `delimiters text omits ${token}`);
  }
  const md = cli('delimiters', '--format', 'markdown').out;
  assert.match(md, /^\| delimiter \| name \| what has to be true at the origin \|/m);
  const json = JSON.parse(cli('delimiters', '--format', 'json').out) as unknown[];
  assert.equal(json.length, 9);
});

test('cache-headers prints the vendor evidence table', () => {
  const text = cli('cache-headers').out;
  for (const header of ['CF-Cache-Status', 'X-Cache', 'X-Vercel-Cache', 'Fastly-Debug-Digest', 'Age']) {
    assert.ok(text.includes(header), `cache-headers omits ${header}`);
  }
  const md = cli('cache-headers', '--format', 'markdown').out;
  assert.match(md, /\| header \| reported by \| values read as a hit \|/);
  assert.match(md, /any value greater than zero/);
});
