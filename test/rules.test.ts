import assert from 'node:assert/strict';
import test from 'node:test';

import { analyse } from '../src/analyse.js';
import { RULES, rule, ruleIds } from '../src/rules/catalogue.js';
import { SEVERITY_ORDER } from '../src/types.js';
import { exampleEntries, findingsFor, ruleIdsIn } from './helpers.js';

const poisoning = analyse(exampleEntries('unkeyed-x-forwarded-host.json'));
const deception = analyse(exampleEntries('css-suffix-deception.har'));
const clean = analyse(exampleEntries('clean-well-configured.json'));
const noise = analyse(exampleEntries('nonce-noise.json'));
const mixed = analyse(exampleEntries('unkeyed-query-cookie-and-directives.json'));
const everything = analyse(
  exampleEntries(
    'unkeyed-x-forwarded-host.json',
    'css-suffix-deception.har',
    'clean-well-configured.json',
    'nonce-noise.json',
    'unkeyed-query-cookie-and-directives.json',
  ),
);

test('the catalogue is internally consistent', () => {
  assert.equal(new Set(ruleIds()).size, RULES.length);
  for (const r of RULES) {
    assert.match(r.id, /^CKL-[UDCE]\d{3}$/);
    assert.ok(SEVERITY_ORDER.includes(r.severity));
    assert.ok(['proof', 'inference'].includes(r.defaultKind));
    assert.ok(r.name.length > 10, `${r.id} needs a name`);
    assert.ok(r.mechanism.length > 60, `${r.id} needs a mechanism sentence`);
    assert.equal(rule(r.id), r);
  }
  assert.throws(() => rule('CKL-X999'), /unknown rule id/);
});

test('every catalogued rule fires on at least one shipped example', () => {
  const fired = new Set(everything.findings.map((f) => f.ruleId));
  const missing = ruleIds().filter((id) => !fired.has(id));
  assert.deepEqual(missing, [], `rules with no worked example: ${missing.join(', ')}`);
});

test('a proof always carries confidence 1 and an inference never does', () => {
  for (const f of everything.findings) {
    if (f.kind === 'proof') assert.equal(f.confidence, 1, `${f.ruleId} proof with confidence ${f.confidence}`);
    else assert.ok(f.confidence > 0 && f.confidence < 1, `${f.ruleId} inference with confidence ${f.confidence}`);
  }
});

test('every finding cites at least one capture entry that exists', () => {
  for (const f of everything.findings) {
    assert.ok(f.entries.length > 0, `${f.ruleId} cites no entry`);
    for (const i of f.entries) {
      assert.ok(i >= 1 && i <= everything.entryCount, `${f.ruleId} cites entry ${i}`);
    }
    assert.ok(f.evidence.length > 0, `${f.ruleId} carries no evidence`);
    assert.ok(f.summary.length > 40, `${f.ruleId} summary is too thin`);
  }
});

test('an inference always says why it is an inference, or rests on a named signal', () => {
  for (const f of everything.findings.filter((x) => x.kind === 'inference')) {
    const labels = f.evidence.map((e) => e.label).join(' ');
    assert.ok(
      labels.includes('why this is an inference') || labels.includes('[inference]') || /inference/.test(JSON.stringify(f.evidence)),
      `${f.ruleId} gives no reason for being an inference`,
    );
  }
});

// --- unkeyed input ------------------------------------------------------

test('CKL-U001 reports the X-Forwarded-Host variation', () => {
  const found = findingsFor(poisoning, 'CKL-U001');
  assert.equal(found.length, 2);
  const home = found.find((f) => f.resource.endsWith('shop.example/'));
  assert.ok(home !== undefined);
  assert.match(home?.summary ?? '', /x-forwarded-host/);
  assert.equal(home?.kind, 'inference');
  assert.deepEqual(home?.entries, [1, 2]);
});

test('CKL-U001 becomes a proof when a cache hit is in evidence', () => {
  const entries = exampleEntries('nonce-noise.json');
  // Flip one body so the pair genuinely varies, keeping the X-Cache: HIT.
  const patched = entries.map((e, i) =>
    i === 1 ? { ...e, response: { ...e.response, body: 'poisoned content' } } : e,
  );
  const found = findingsFor(analyse(patched), 'CKL-U001');
  assert.equal(found.length, 1);
  assert.equal(found[0]?.kind, 'proof');
  assert.match(JSON.stringify(found[0]?.evidence), /cache evidence/);
});

test('CKL-U001 is NOT reported when the only difference is per-response noise', () => {
  assert.equal(findingsFor(noise, 'CKL-U001').length, 0);
  assert.equal(noise.findings.length, 0);
});

test('CKL-U002 names where the reflected value landed', () => {
  const found = findingsFor(poisoning, 'CKL-U002');
  assert.equal(found.length, 2);
  const home = found.find((f) => f.resource.includes('shop.example/'));
  const labels = (home?.evidence ?? []).map((e) => e.label);
  assert.ok(labels.some((l) => l.includes('<script src>')));
  assert.ok(labels.some((l) => l.includes('canonical link')));
  assert.ok(labels.some((l) => l.includes('og: meta tag')));
  assert.ok(labels.includes('attacker control'));
});

test('CKL-U002 parses the Forwarded header and finds the host in a Location', () => {
  const login = findingsFor(poisoning, 'CKL-U002').find((f) => f.resource.includes('/login'));
  assert.ok(login !== undefined);
  assert.match(login?.summary ?? '', /Forwarded/);
  assert.ok((login?.evidence ?? []).some((e) => e.label === 'landed in the Location header'));
});

test('CKL-U002 is not reported when a routing header changes nothing', () => {
  assert.equal(findingsFor(clean, 'CKL-U002').length, 0);
});

test('CKL-U003 reports the locale query parameter', () => {
  const found = findingsFor(mixed, 'CKL-U003');
  assert.equal(found.length, 1);
  assert.match(found[0]?.summary ?? '', /lang/);
  assert.equal(found[0]?.kind, 'inference');
});

test('CKL-U004 reports a reordered query that shares one key', () => {
  const found = findingsFor(mixed, 'CKL-U004');
  assert.equal(found.length, 1);
  assert.match(JSON.stringify(found[0]?.evidence), /parameter-order/);
  assert.equal(found[0]?.kind, 'proof');
});

test('CKL-U005 reports the cookie variation and names the cookie', () => {
  const found = findingsFor(mixed, 'CKL-U005');
  assert.equal(found.length, 1);
  assert.match(found[0]?.summary ?? '', /cookie session/);
});

test('CKL-U005 is suppressed when the origin declares Vary: Cookie', () => {
  assert.equal(findingsFor(clean, 'CKL-U005').length, 0);
});

test('CKL-U006 reports Vary: *', () => {
  assert.equal(findingsFor(mixed, 'CKL-U006').length, 1);
});

test('CKL-U007 reports a Vary token the origin does not read', () => {
  const found = findingsFor(mixed, 'CKL-U007');
  assert.equal(found.length, 1);
  assert.match(found[0]?.summary ?? '', /user-agent/);
});

test('CKL-U008 reports Vary: User-Agent', () => {
  assert.equal(findingsFor(mixed, 'CKL-U008').length, 1);
});

test('CKL-U009 reports both the HEAD and the Range case', () => {
  const found = findingsFor(mixed, 'CKL-U009');
  assert.equal(found.length, 2);
  assert.ok(found.some((f) => f.resource.startsWith('HEAD ')));
  assert.ok(found.some((f) => JSON.stringify(f.evidence).includes('Range')));
});

test('CKL-U010 reports a fat GET as a proof', () => {
  const found = findingsFor(mixed, 'CKL-U010');
  assert.equal(found.length, 1);
  assert.equal(found[0]?.kind, 'proof');
  assert.match(found[0]?.summary ?? '', /request body/);
});

// --- deception ----------------------------------------------------------

test('CKL-D001 reports the .css suffix as a proof, naming the dynamic route', () => {
  const found = findingsFor(deception, 'CKL-D001');
  assert.ok(found.length >= 2);
  const css = found.find((f) => f.resource.endsWith('/account.css'));
  assert.ok(css !== undefined);
  assert.equal(css?.kind, 'proof');
  assert.match(JSON.stringify(css?.evidence), /strip-static-extension/);
  assert.match(JSON.stringify(css?.evidence), /identical content/);
});

test('CKL-D001 states what identified the user', () => {
  const css = findingsFor(deception, 'CKL-D001').find((f) => f.resource.endsWith('/account.css'));
  const identity = (css?.evidence ?? []).find((e) => e.label === 'what identified the user');
  assert.ok(identity !== undefined);
  assert.match(identity?.detail ?? '', /session cookie|e-mail address|greeting/);
});

test('CKL-D002 names the delimiters the origin tolerated and those it did not show', () => {
  const found = findingsFor(deception, 'CKL-D002');
  assert.ok(found.length >= 2);
  const semi = found.find((f) => f.resource.includes(';ckl.js'));
  assert.ok(semi !== undefined);
  const labels = (semi?.evidence ?? []).map((e) => e.label);
  assert.ok(labels.includes('delimiter ";" tolerated'));
  assert.ok(labels.includes('not shown tolerated by this capture'));
});

test('CKL-D003 reports the static-prefix escape', () => {
  const found = findingsFor(deception, 'CKL-D003');
  assert.equal(found.length, 1);
  assert.match(found[0]?.summary ?? '', /\/static\//);
  assert.match(JSON.stringify(found[0]?.evidence), /percent-decode/);
});

test('CKL-D004 is critical and says what identified the user', () => {
  const found = findingsFor(deception, 'CKL-D004');
  assert.ok(found.length >= 1);
  for (const f of found) {
    assert.equal(f.severity, 'critical');
    assert.match(f.summary, /What identified the user/);
    assert.match(JSON.stringify(f.evidence), /storability/);
  }
});

test('CKL-D004 is not reported for a no-store response', () => {
  assert.equal(findingsFor(clean, 'CKL-D004').length, 0);
});

test('CKL-D005 reports two path spellings that resolve to one resource', () => {
  const found = findingsFor(mixed, 'CKL-D005');
  assert.equal(found.length, 1);
  assert.match(found[0]?.summary ?? '', /normalise to/);
  assert.equal(found[0]?.kind, 'proof');
});

// --- directives ---------------------------------------------------------

test('CKL-C001 reports private with a positive max-age', () => {
  const found = findingsFor(mixed, 'CKL-C001');
  assert.ok(found.length >= 1);
  assert.match(found[0]?.summary ?? '', /private and max-age=600/);
});

test('CKL-C002 reports no-cache without no-store on an authenticated response', () => {
  const found = findingsFor(mixed, 'CKL-C002');
  assert.equal(found.length, 1);
  assert.match(JSON.stringify(found[0]?.evidence), /Authorization/);
});

test('CKL-C003 reports s-maxage overriding max-age=0', () => {
  const found = findingsFor(mixed, 'CKL-C003');
  assert.equal(found.length, 1);
  assert.match(found[0]?.summary ?? '', /s-maxage=3600/);
  assert.equal(found[0]?.severity, 'high');
});

test('CKL-C004 reports revalidation without must-revalidate', () => {
  assert.ok(findingsFor(mixed, 'CKL-C004').length >= 1);
});

test('CKL-C005 quantifies the stale exposure window', () => {
  const found = findingsFor(mixed, 'CKL-C005');
  assert.equal(found.length, 1);
  assert.match(JSON.stringify(found[0]?.evidence), /stale window 600s/);
});

test('CKL-C006 reports Pragma on its own', () => {
  const found = findingsFor(mixed, 'CKL-C006');
  assert.equal(found.length, 1);
  assert.match(found[0]?.resource ?? '', /\/legacy/);
});

test('CKL-C007 reports a response with no cache controls at all', () => {
  const found = findingsFor(mixed, 'CKL-C007');
  assert.ok(found.length >= 1);
  assert.ok(found.some((f) => f.resource.includes('/status.json')));
});

test('no directive rule fires on the well-configured capture', () => {
  assert.deepEqual(
    ruleIdsIn(clean).filter((id) => id.startsWith('CKL-C')),
    [],
  );
});

// --- evidence -----------------------------------------------------------

test('CKL-E001 reports the cache hit on the authenticated response', () => {
  const found = findingsFor(deception, 'CKL-E001');
  assert.equal(found.length, 1);
  assert.equal(found[0]?.severity, 'critical');
  assert.equal(found[0]?.kind, 'proof');
  assert.match(found[0]?.summary ?? '', /CF-Cache-Status: HIT/);
});

test('CKL-E002 reports a positive Age on the same response', () => {
  const found = findingsFor(deception, 'CKL-E002');
  assert.equal(found.length, 1);
  assert.match(found[0]?.summary ?? '', /Age: 43/);
});

test('a cache hit on an impersonal asset is NOT reported', () => {
  assert.equal(findingsFor(clean, 'CKL-E001').length, 0);
  assert.equal(findingsFor(clean, 'CKL-E002').length, 0);
});

test('the cache-header table lists every cache-status header, hit or not', () => {
  assert.equal(deception.cacheHeaders.length, 5);
  assert.ok(deception.cacheHeaders.some((r) => r.header === 'CF-Cache-Status' && r.note.includes('Cloudflare')));
  assert.ok(deception.cacheHeaders.some((r) => r.header === 'Age'));
  assert.ok(clean.cacheHeaders.some((r) => r.note.includes('served from store')));
});

// --- the clean capture --------------------------------------------------

test('the well-configured capture produces no findings at all', () => {
  assert.deepEqual(clean.findings, []);
  assert.equal(clean.entryCount, 5);
  assert.equal(clean.keys.length, 3);
});

test('findings are sorted by severity, then proofs before inferences', () => {
  const order = everything.findings.map((f) => SEVERITY_ORDER.indexOf(f.severity));
  assert.deepEqual([...order].sort((a, b) => a - b), order);
  for (let i = 1; i < everything.findings.length; i += 1) {
    const prev = everything.findings[i - 1];
    const cur = everything.findings[i];
    if (prev?.severity === cur?.severity && prev?.kind !== cur?.kind) {
      assert.equal(prev?.kind, 'proof', 'an inference was sorted above a proof of the same severity');
    }
  }
});
