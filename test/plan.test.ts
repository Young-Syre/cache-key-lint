import assert from 'node:assert/strict';
import test from 'node:test';

import { formatPlan } from '../src/format.js';
import { BUSTER_PARAM, CACHE_BUSTER_WARNING, buildPlan } from '../src/plan.js';
import { DELIMITERS } from '../src/url.js';
import { exampleEntries } from './helpers.js';

const entries = exampleEntries('unkeyed-query-cookie-and-directives.json');
const plan = buildPlan('https://www.example/search?q=shoes&lang=en', entries);

test('every probe carries a cache-buster', () => {
  assert.ok(plan.probes.length > 30, `only ${plan.probes.length} probes`);
  for (const probe of plan.probes) {
    assert.ok(probe.url.includes(`${BUSTER_PARAM}=`), `probe has no buster: ${probe.url}`);
  }
});

test('buster tokens are unique and deterministic', () => {
  const tokens = plan.probes
    .map((p) => /cklcb=([A-Za-z0-9]+)/.exec(p.url)?.[1] ?? '')
    .filter((t) => t !== '');
  assert.equal(tokens.length, plan.probes.length);
  assert.equal(new Set(tokens).size, tokens.length);
  const again = buildPlan('https://www.example/search?q=shoes&lang=en', entries);
  assert.deepEqual(again.probes.map((p) => p.url), plan.probes.map((p) => p.url));
});

test('the buster prefix is configurable', () => {
  const custom = buildPlan('https://www.example/search', entries, { buster: 'probe-' });
  assert.ok(custom.probes[0]?.url.includes('cklcb=probe-001'));
});

test('the cache-buster warning is present and explains the production risk', () => {
  assert.deepEqual(plan.warning, CACHE_BUSTER_WARNING);
  const joined = plan.warning.join(' ');
  assert.match(joined, /real users/);
  assert.match(joined, /purged/);
  assert.match(joined, /Change one thing per probe/);
  assert.match(joined, /authorisation/i);
});

test('every routing header in the catalogue gets a probe', () => {
  const headerProbes = plan.probes.filter((p) => p.group === 'unkeyed-header');
  const names = headerProbes.flatMap((p) => p.headers.map((h) => h.name));
  for (const expected of ['X-Forwarded-Host', 'X-Forwarded-Scheme', 'X-Original-URL', 'X-Rewrite-URL', 'Forwarded', 'X-Forwarded-Prefix', 'X-Forwarded-Port', 'X-Host']) {
    assert.ok(names.includes(expected), `no probe for ${expected}`);
  }
  assert.ok(names.includes('X-Timer'), 'the control probe is missing');
});

test('each header probe injects a value that is traceable back to its own probe', () => {
  for (const probe of plan.probes.filter((p) => p.group === 'unkeyed-header')) {
    const token = /cklcb=([A-Za-z0-9-]+)/.exec(probe.url)?.[1];
    assert.ok(token !== undefined);
    assert.equal(probe.headers[0]?.value, `ckl-${token}.invalid`);
  }
});

test('every delimiter in the matrix gets a probe for each static extension', () => {
  const delimiterProbes = plan.probes.filter((p) => p.group === 'delimiter');
  assert.equal(delimiterProbes.length, DELIMITERS.length * 2);
  for (const d of DELIMITERS) {
    assert.ok(
      delimiterProbes.some((p) => p.purpose.includes(`"${d.token}ckl.css"`) || p.purpose.includes(`"${d.token}ckl.js"`)),
      `no delimiter probe for ${d.token}`,
    );
  }
});

test('the query permutation set covers all six spelling classes plus a buster-only probe', () => {
  const labels = plan.probes.filter((p) => p.group === 'query-permutation').map((p) => p.purpose);
  for (const expected of [
    'parameter order',
    'duplicate parameter',
    'name case',
    'semicolon separator',
    'empty parameter',
    'encoded hash',
    'buster only',
  ]) {
    assert.ok(labels.some((l) => l.includes(expected)), `no permutation for ${expected}`);
  }
});

test('the permutations reuse a parameter observed in the capture', () => {
  const order = plan.probes.find((p) => p.purpose.includes('parameter order'));
  assert.ok(order?.url.includes('q=shoes'), `expected the captured parameter, got ${order?.url}`);
});

test('the cookie probe names the cookie seen in the capture', () => {
  const cookie = plan.probes.find((p) => p.group === 'cookie');
  assert.ok(cookie !== undefined);
  assert.match(cookie?.headers[0]?.value ?? '', /^session=CKL-PROBE-/);
  assert.match(cookie?.expect ?? '', /no Cookie header at all/);
});

test('the method and Range probes come as a storing probe and a confirming one', () => {
  const group = plan.probes.filter((p) => p.group === 'method-and-range');
  assert.equal(group.length, 2);
  assert.equal(group[0]?.method, 'HEAD');
  assert.match(group[0]?.expect ?? '', /then a GET to the same buster value/);
  assert.equal(group[1]?.headers[0]?.name, 'Range');
});

test('the fat-GET probe exists and explains that no cache keys on a body', () => {
  const fat = plan.probes.find((p) => p.group === 'fat-get');
  assert.equal(fat?.method, 'GET');
  assert.match(fat?.purpose ?? '', /No cache keys on one/);
});

test('every probe states a purpose and what to look for', () => {
  for (const probe of plan.probes) {
    assert.ok(probe.purpose.length > 20, `thin purpose: ${probe.purpose}`);
    assert.ok(probe.expect.length > 20, `thin expectation: ${probe.expect}`);
    assert.ok(probe.group.length > 0);
  }
});

test('the plan reports what the capture already established about the key', () => {
  const notes = plan.notesFromCapture.join(' ');
  assert.match(notes, /3 observations of this resource/);
  assert.match(notes, /inferred key confidence/);
  assert.match(notes, /not in the key/);
});

test('a URL absent from the capture produces the generic matrix and says so', () => {
  const generic = buildPlan('https://other.example/unseen', entries);
  assert.match(generic.notesFromCapture.join(' '), /contains no entry for this URL/);
  assert.ok(generic.probes.length > 30);
});

test('plan works with no capture at all', () => {
  const bare = buildPlan('https://other.example/unseen', []);
  assert.ok(bare.probes.length > 30);
  assert.match(bare.notesFromCapture.join(' '), /no entry for this URL/);
});

test('the text and markdown renderings both lead with the warning', () => {
  const text = formatPlan(plan, 'text');
  assert.match(text, /CACHE-BUSTER DISCIPLINE — READ BEFORE SENDING ANYTHING/);
  assert.ok(text.indexOf('CACHE-BUSTER DISCIPLINE') < text.indexOf('PROBES ('));
  const md = formatPlan(plan, 'markdown');
  assert.match(md, /> \*\*Cache-buster discipline/);
  assert.ok(md.indexOf('Cache-buster discipline') < md.indexOf('## Probes'));
});

test('the JSON rendering round-trips', () => {
  const parsed = JSON.parse(formatPlan(plan, 'json')) as typeof plan;
  assert.equal(parsed.probes.length, plan.probes.length);
  assert.equal(parsed.target, plan.target);
  assert.deepEqual(parsed.warning, [...CACHE_BUSTER_WARNING]);
});
