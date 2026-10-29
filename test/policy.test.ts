import assert from 'node:assert/strict';
import test from 'node:test';

import { makeHeader } from '../src/headers.js';
import { ageSeconds, directiveSeconds, parseDirectives, requestAuth, storability } from '../src/policy.js';
import type { CapturedRequest, CapturedResponse } from '../src/types.js';

function req(headers: [string, string][] = [], method = 'GET'): CapturedRequest {
  return { method, url: 'https://a.example/x', headers: headers.map(([n, v]) => makeHeader(n, v)), body: null };
}
function res(headers: [string, string][] = [], status = 200): CapturedResponse {
  return { status, headers: headers.map(([n, v]) => makeHeader(n, v)), body: '' };
}

test('parseDirectives reads tokens and values, lowercasing names', () => {
  const d = parseDirectives('Public, max-age=600, s-maxage="30", no-transform');
  assert.equal(d.has('public'), true);
  assert.equal(d.get('max-age'), '600');
  assert.equal(d.get('s-maxage'), '30');
  assert.equal(d.get('public'), null);
  assert.equal(d.size, 4);
});

test('parseDirectives of a null header is empty', () => {
  assert.equal(parseDirectives(null).size, 0);
});

test('directiveSeconds parses only integers', () => {
  const d = parseDirectives('max-age=600, s-maxage=abc, no-cache');
  assert.equal(directiveSeconds(d, 'max-age'), 600);
  assert.equal(directiveSeconds(d, 's-maxage'), null);
  assert.equal(directiveSeconds(d, 'no-cache'), null);
  assert.equal(directiveSeconds(d, 'absent'), null);
});

test('no-store forbids storage', () => {
  const s = storability(req(), res([['Cache-Control', 'no-store, private']]));
  assert.equal(s.mayStore, false);
  assert.match(s.reason, /no-store/);
});

test('private excludes shared caches', () => {
  assert.equal(storability(req(), res([['Cache-Control', 'private, max-age=600']])).mayStore, false);
});

test('private is overridden for shared caches by s-maxage', () => {
  const s = storability(req(), res([['Cache-Control', 'private, s-maxage=60']]));
  assert.equal(s.mayStore, true);
  assert.match(s.reason, /overridden for shared caches/);
});

test('an Authorization-gated response is not stored without public, s-maxage or must-revalidate', () => {
  const r = req([['Authorization', 'Bearer FIXTURE-TOKEN-A']]);
  assert.equal(storability(r, res([['Cache-Control', 'max-age=600']])).mayStore, false);
  assert.equal(storability(r, res([['Cache-Control', 'public, max-age=600']])).mayStore, true);
  assert.equal(storability(r, res([['Cache-Control', 's-maxage=600']])).mayStore, true);
  assert.equal(storability(r, res([['Cache-Control', 'must-revalidate']])).mayStore, true);
  assert.match(storability(r, res([['Cache-Control', 'public']])).reason, /RFC 9111/);
});

test('no-cache permits storage but requires revalidation', () => {
  const s = storability(req(), res([['Cache-Control', 'no-cache']]));
  assert.equal(s.mayStore, true);
  assert.equal(s.requiresRevalidation, true);
});

test('max-age=0 permits storage without reuse', () => {
  const s = storability(req(), res([['Cache-Control', 'max-age=0']]));
  assert.equal(s.mayStore, true);
  assert.equal(s.requiresRevalidation, true);
});

test('a non-cacheable method is not stored', () => {
  assert.equal(storability(req([], 'POST'), res([['Cache-Control', 'public']])).mayStore, false);
});

test('a CDN-targeted directive is folded into the shared-cache verdict', () => {
  const s = storability(req(), res([['Cache-Control', 'private'], ['CDN-Cache-Control', 's-maxage=120']]));
  assert.equal(s.mayStore, true);
  assert.equal(s.cdnDirectives.get('s-maxage'), '120');
});

test('Surrogate-Control is read the same way', () => {
  const s = storability(req(), res([['Surrogate-Control', 'max-age=60']]));
  assert.equal(s.mayStore, true);
});

test('no Cache-Control plus a heuristically cacheable status is storable', () => {
  const s = storability(req(), res([], 200));
  assert.equal(s.mayStore, true);
  assert.equal(s.heuristic, true);
  assert.match(s.reason, /heuristically cacheable/);
});

test('no Cache-Control plus a non-heuristic status is not storable', () => {
  assert.equal(storability(req(), res([], 500)).mayStore, false);
});

test('Expires supplies freshness when Cache-Control is absent', () => {
  const s = storability(req(), res([['Expires', 'Wed, 14 Jan 2026 09:12:00 GMT']]));
  assert.equal(s.mayStore, true);
  assert.equal(s.heuristic, false);
});

test('requestAuth classifies credentials', () => {
  const a = requestAuth(req([['Authorization', 'Bearer FIXTURE-TOKEN-A'], ['Cookie', 'session=X; theme=dark']]));
  assert.equal(a.authorizationHeader, true);
  assert.equal(a.scheme, 'Bearer');
  assert.deepEqual(a.sessionCookies, ['session']);
  assert.deepEqual(a.anyCookies, ['session', 'theme']);
});

test('requestAuth on an anonymous request reports nothing', () => {
  const a = requestAuth(req());
  assert.equal(a.authorizationHeader, false);
  assert.equal(a.scheme, null);
  assert.deepEqual(a.sessionCookies, []);
});

test('ageSeconds reads Age and tolerates nonsense', () => {
  assert.equal(ageSeconds(res([['Age', '43']])), 43);
  assert.equal(ageSeconds(res([['Age', 'soon']])), null);
  assert.equal(ageSeconds(res()), null);
});
