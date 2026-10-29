import assert from 'node:assert/strict';
import test from 'node:test';

import { DEFAULT_NORMALISERS, NormaliserSet, parseNormaliserConfig } from '../src/normalise.js';

const set = NormaliserSet.default();

test('every default normaliser has an id and a description', () => {
  assert.ok(DEFAULT_NORMALISERS.length >= 12);
  for (const n of DEFAULT_NORMALISERS) {
    assert.ok(n.id.length > 0);
    assert.ok(n.description.length > 10, `${n.id} needs a description`);
    assert.ok(n.pattern instanceof RegExp);
  }
});

test('normaliser ids are unique', () => {
  const ids = DEFAULT_NORMALISERS.map((n) => n.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('a response differing only in a CSP nonce is equivalent', () => {
  const a = `<meta content="script-src 'nonce-aaaaaaaa'"><script nonce="aaaaaaaa"></script>`;
  const b = `<meta content="script-src 'nonce-bbbbbbbb'"><script nonce="bbbbbbbb"></script>`;
  assert.equal(set.equivalent(a, b), true);
});

test('a response differing only in a CSRF meta token is equivalent', () => {
  const a = '<meta name="csrf-token" content="a1b2c3d4e5f60718">';
  const b = '<meta name="csrf-token" content="99887766554433aa">';
  assert.equal(set.equivalent(a, b), true);
});

test('a response differing only in a JSON csrf field is equivalent', () => {
  assert.equal(
    set.equivalent('{"csrfToken":"abcdefgh1234"}', '{"csrfToken":"zyxwvuts9876"}'),
    true,
  );
});

test('a response differing only in an ISO timestamp is equivalent', () => {
  assert.equal(
    set.equivalent('generated 2026-01-14T09:12:00Z', 'generated 2026-02-01T11:00:59.123Z'),
    true,
  );
});

test('a response differing only in an HTTP date is equivalent', () => {
  assert.equal(
    set.equivalent('Wed, 14 Jan 2026 09:12:00 GMT', 'Thu, 15 Jan 2026 10:00:00 GMT'),
    true,
  );
});

test('a response differing only in epoch seconds or millis is equivalent', () => {
  assert.equal(set.equivalent('t=1768381920', 't=1768468320'), true);
  assert.equal(set.equivalent('t=1768381920123', 't=1768468320456'), true);
});

test('a response differing only in a UUID is equivalent', () => {
  assert.equal(
    set.equivalent(
      'id 3f2504e0-4f89-41d3-9a0c-0305e82c3301',
      'id 9c858901-8a57-4791-81fe-4c455b099bc9',
    ),
    true,
  );
});

test('a response differing only in a bundler hash path is equivalent', () => {
  assert.equal(
    set.equivalent('<script src="/_next/static/aBcDeFgH12/main.js">', '<script src="/_next/static/zZyYxXwW98/main.js">'),
    true,
  );
});

test('a response differing only in an asset content hash is equivalent', () => {
  assert.equal(
    set.equivalent('<script src="/assets/app.1f3a9c2b.js">', '<script src="/assets/app.8e7d6c5b.js">'),
    true,
  );
});

test('a response differing only in a cache-buster query is equivalent', () => {
  assert.equal(set.equivalent('<img src="/a.png?v=12345">', '<img src="/a.png?v=98765">'), true);
});

test('a response differing only in a request id is equivalent', () => {
  assert.equal(set.equivalent('request_id: abc12345xyz', 'request_id: zzz99887766'), true);
});

test('a response differing only in an ETag literal is equivalent', () => {
  assert.equal(set.equivalent('etag W/"abcdefgh1234"', 'etag W/"zyxwvuts9876"'), true);
});

test('a response differing only in whitespace is equivalent', () => {
  assert.equal(set.equivalent('<p>hello</p>\n\n  <p>there</p>', '<p>hello</p> <p>there</p>'), true);
});

test('a real content difference is NOT masked', () => {
  assert.equal(set.equivalent('Signed in as Ada', 'Signed in as Grace'), false);
  assert.equal(set.equivalent('<a href="//cdn.example/x.js">', '<a href="//evil.invalid/x.js">'), false);
  assert.equal(set.equivalent('{"scope":"mine"}', '{"scope":"all"}'), false);
});

test('a null body normalises to the empty string and matches another null', () => {
  assert.equal(set.apply(null), '');
  assert.equal(set.equivalent(null, null), true);
  assert.equal(set.equivalent(null, 'x'), false);
});

test('an empty normaliser set compares bodies verbatim', () => {
  const none = new NormaliserSet([]);
  assert.equal(none.equivalent('a  b', 'a b'), false);
  assert.equal(none.equivalent('a b', 'a b'), true);
});

test('ids() lists the applied normalisers in order', () => {
  assert.deepEqual(set.ids()[0], 'csp-nonce');
  assert.equal(set.ids().at(-1), 'whitespace');
});

test('parseNormaliserConfig accepts a well-formed file', () => {
  const parsed = parseNormaliserConfig(
    { normalisers: [{ id: 'order-no', description: 'order numbers', pattern: 'ORD-\\d+', flags: 'gi' }] },
    'custom.json',
  );
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.id, 'order-no');
  assert.ok(parsed[0]?.pattern.flags.includes('g'));
  const custom = new NormaliserSet(parsed);
  assert.equal(custom.equivalent('ORD-1', 'ORD-22222'), true);
});

test('parseNormaliserConfig forces the global flag on', () => {
  const parsed = parseNormaliserConfig({ normalisers: [{ id: 'x', pattern: 'a' }] }, 'c.json');
  assert.ok(parsed[0]?.pattern.flags.includes('g'));
});

test('parseNormaliserConfig honours an explicit replacement', () => {
  const parsed = parseNormaliserConfig(
    { normalisers: [{ id: 'keepname', pattern: '(name=)\\w+', replacement: '$1X' }] },
    'c.json',
  );
  assert.equal(new NormaliserSet(parsed).apply('name=ada'), 'name=X');
});

test('parseNormaliserConfig rejects malformed input with a useful message', () => {
  assert.throws(() => parseNormaliserConfig([], 'c.json'), /normalisers" array/);
  assert.throws(() => parseNormaliserConfig({}, 'c.json'), /normalisers" array/);
  assert.throws(() => parseNormaliserConfig({ normalisers: [1] }, 'c.json'), /expected an object/);
  assert.throws(() => parseNormaliserConfig({ normalisers: [{ pattern: 'a' }] }, 'c.json'), /"id" must be/);
  assert.throws(() => parseNormaliserConfig({ normalisers: [{ id: 'a' }] }, 'c.json'), /"pattern" must be/);
  assert.throws(
    () => parseNormaliserConfig({ normalisers: [{ id: 'a', pattern: '(' }] }, 'c.json'),
    /invalid regular expression/,
  );
  assert.throws(
    () => parseNormaliserConfig({ normalisers: [{ id: 'a', pattern: 'x', flags: 5 }] }, 'c.json'),
    /"flags" must be/,
  );
});
