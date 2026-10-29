import assert from 'node:assert/strict';
import test from 'node:test';

import { analyse } from '../src/analyse.js';
import { groupByResource, pairs, requestDelta, responseDelta } from '../src/group.js';
import { inferKey, inferKeys } from '../src/key.js';
import { NormaliserSet } from '../src/normalise.js';
import { exampleEntries } from './helpers.js';

const norms = NormaliserSet.default();

function keyFor(file: string, url: string) {
  const groups = groupByResource(exampleEntries(file));
  const group = groups.find((g) => g.key === url);
  assert.ok(group !== undefined, `no group for ${url}`);
  return inferKey(group, norms);
}

test('host and path are always reported as in the key, and labelled as assumptions', () => {
  const key = keyFor('unkeyed-x-forwarded-host.json', 'shop.example/');
  const components = key.inKey.map((c) => c.component);
  assert.ok(components.includes('host'));
  assert.ok(components.includes('path'));
  for (const c of key.inKey.filter((x) => x.component === 'host' || x.component === 'path')) {
    assert.match(c.evidence, /^assumed/);
  }
});

test('a header the response varies with lands in notInKey as an inference', () => {
  const key = keyFor('unkeyed-x-forwarded-host.json', 'shop.example/');
  const entry = key.notInKey.find((c) => c.component === 'header:x-forwarded-host');
  assert.ok(entry !== undefined);
  assert.match(entry?.evidence ?? '', /inferred, not proven/);
});

test('a Vary token lands in inKey citing the origin', () => {
  const key = keyFor('css-suffix-deception.har', 'app.example/account');
  const cookie = key.inKey.find((c) => c.component === 'header:cookie');
  assert.ok(cookie !== undefined);
  assert.match(cookie?.evidence ?? '', /declares Vary: cookie/);
});

test('a hit on an equivalent body places a component outside the key with real evidence', () => {
  const key = keyFor('nonce-noise.json', 'status.example/overview');
  const entry = key.notInKey.find((c) => c.component === 'header:x-forwarded-host');
  assert.ok(entry !== undefined);
  assert.match(entry?.evidence ?? '', /served from the cache store/);
  assert.match(entry?.evidence ?? '', /shared one key/);
});

test('a component that changed nothing is reported as untested, not as absent from the key', () => {
  const key = keyFor('clean-well-configured.json', 'www.example/');
  const entry = key.unknown.find((c) => c.component === 'header:x-forwarded-host');
  assert.ok(entry !== undefined);
  assert.match(entry?.evidence ?? '', /cannot place it on either side/);
});

test('the method is always reported as untested when only one was observed', () => {
  const key = keyFor('unkeyed-x-forwarded-host.json', 'shop.example/');
  assert.ok(key.unknown.some((c) => c.component === 'method'));
});

test('Vary: * is reported as making every stored response unselectable', () => {
  const key = keyFor('unkeyed-query-cookie-and-directives.json', 'www.example/experiments');
  assert.ok(key.notInKey.some((c) => c.component === 'any stored response'));
});

test('a query parameter never varied on its own is listed as untested', () => {
  const key = keyFor('unkeyed-query-cookie-and-directives.json', 'www.example/graph');
  assert.ok(key.unknown.some((c) => c.component === 'query:op'));
});

test('a query parameter the response varies with is listed as not in the key', () => {
  const key = keyFor('unkeyed-query-cookie-and-directives.json', 'www.example/search');
  assert.ok(key.notInKey.some((c) => c.component === 'query:lang'));
});

test('confidence is bounded and its basis is itemised', () => {
  for (const key of inferKeys(groupByResource(exampleEntries('unkeyed-query-cookie-and-directives.json')), norms)) {
    assert.ok(key.confidence >= 0.1 && key.confidence <= 0.95, `confidence ${key.confidence}`);
    assert.ok(key.basis.length >= 1);
    assert.match(key.basis[0] ?? '', /^base 0\.30$/);
  }
});

test('confidence rises with cache evidence, a Vary header and an attributed pair', () => {
  const withEverything = keyFor('nonce-noise.json', 'status.example/overview');
  assert.equal(withEverything.confidence, 0.75);
  const bare = keyFor('unkeyed-query-cookie-and-directives.json', 'www.example/legacy');
  assert.equal(bare.confidence, 0.3);
  assert.ok(withEverything.confidence > bare.confidence);
});

test('a pair differing in more than one component is counted against the confidence', () => {
  const key = keyFor('unkeyed-query-cookie-and-directives.json', 'www.example/report.pdf');
  assert.ok(key.basis.some((b) => b.includes('more than one request component')));
});

test('every distinct resource in the capture gets exactly one inferred key', () => {
  const report = analyse(exampleEntries('unkeyed-query-cookie-and-directives.json'));
  const urls = report.keys.map((k) => k.url);
  assert.equal(new Set(urls).size, urls.length);
  assert.deepEqual([...urls].sort(), urls, 'keys should be sorted by resource');
  assert.ok(urls.includes('www.example/search'));
  assert.ok(urls.includes('www.example/profile'));
});

test('observations counts the entries behind each key', () => {
  const key = keyFor('unkeyed-query-cookie-and-directives.json', 'www.example/search');
  assert.equal(key.observations, 3);
  assert.deepEqual(key.methods, ['GET']);
});

// --- diffing primitives -------------------------------------------------

test('requestDelta attributes a single differing header', () => {
  const entries = exampleEntries('unkeyed-x-forwarded-host.json');
  const delta = requestDelta(entries[0] as never, entries[1] as never);
  assert.deepEqual(delta.headers, ['x-forwarded-host']);
  assert.equal(delta.dimensions, 1);
  assert.equal(delta.methodDiffers, false);
  assert.equal(delta.bodyDiffers, false);
});

test('requestDelta ignores transport and conditional-request noise', () => {
  const entries = exampleEntries('unkeyed-x-forwarded-host.json');
  const a = entries[0] as never as { request: { headers: unknown[] } };
  const noisy = {
    ...(entries[0] as object),
    request: {
      ...(entries[0] as never as { request: object }).request,
      headers: [
        ...(a.request.headers as never[]),
        { name: 'Content-Length', lower: 'content-length', value: '12' },
        { name: 'If-None-Match', lower: 'if-none-match', value: '"x"' },
        { name: 'Sec-Fetch-Mode', lower: 'sec-fetch-mode', value: 'cors' },
      ],
    },
  };
  const delta = requestDelta(entries[0] as never, noisy as never);
  assert.equal(delta.dimensions, 0);
});

test('requestDelta detects a cookie value change without reporting the Cookie header', () => {
  const entries = exampleEntries('clean-well-configured.json');
  const delta = requestDelta(entries[0] as never, entries[1] as never);
  assert.deepEqual(delta.cookies, ['session']);
  assert.equal(delta.headers.includes('cookie'), false);
  assert.equal(delta.dimensions, 1);
});

test('requestDelta classifies a reordered query as a spelling difference, not a value difference', () => {
  const entries = exampleEntries('unkeyed-query-cookie-and-directives.json');
  const delta = requestDelta(entries[0] as never, entries[2] as never);
  assert.deepEqual(delta.queryValues, []);
  assert.deepEqual(delta.querySpelling, ['parameter-order']);
  assert.equal(delta.dimensions, 1);
});

test('responseDelta treats a nonce-only difference as no variation', () => {
  const entries = exampleEntries('nonce-noise.json');
  const delta = responseDelta(entries[0] as never, entries[1] as never, norms);
  assert.equal(delta.bodyDiffers, false);
  assert.equal(delta.varied, false);
});

test('responseDelta reports a changed Location as a variation', () => {
  const entries = exampleEntries('unkeyed-x-forwarded-host.json');
  const delta = responseDelta(entries[2] as never, entries[3] as never, norms);
  assert.deepEqual(delta.headers, ['location']);
  assert.equal(delta.varied, true);
});

test('pairs() yields every unordered pair in capture order', () => {
  assert.deepEqual(pairs([1, 2, 3]), [
    [1, 2],
    [1, 3],
    [2, 3],
  ]);
  assert.deepEqual(pairs([1]), []);
});

test('groupByResource groups on host and path, ignoring the query', () => {
  const groups = groupByResource(exampleEntries('unkeyed-query-cookie-and-directives.json'));
  const search = groups.find((g) => g.key === 'www.example/search');
  assert.equal(search?.entries.length, 3);
  assert.equal(search?.host, 'www.example');
  assert.equal(search?.path, '/search');
});
