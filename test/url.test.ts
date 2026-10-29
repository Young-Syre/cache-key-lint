import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DELIMITERS,
  cacheVisibleExtension,
  canonicalQuery,
  decodeOnce,
  delimiterSplits,
  looksStaticToCache,
  originCandidates,
  parseQuery,
  parseUrl,
  resolveDotSegments,
  serialiseQuery,
} from '../src/url.js';

test('parseUrl splits an absolute URL into its cache-relevant parts', () => {
  const u = parseUrl('https://shop.example:8443/a/b?x=1&y=2#frag');
  assert.equal(u.origin, 'https://shop.example:8443');
  assert.equal(u.host, 'shop.example:8443');
  assert.equal(u.path, '/a/b');
  assert.equal(u.search, 'x=1&y=2');
  assert.equal(u.fragment, 'frag');
  assert.equal(u.params.length, 2);
});

test('parseUrl accepts a path-only entry', () => {
  const u = parseUrl('/account');
  assert.equal(u.origin, '');
  assert.equal(u.host, '');
  assert.equal(u.path, '/account');
});

test('parseUrl normalises an empty path to /', () => {
  assert.equal(parseUrl('https://shop.example').path, '/');
  assert.equal(parseUrl('https://shop.example?a=1').path, '/');
});

test('parseUrl lowercases the host but not the path', () => {
  const u = parseUrl('https://SHOP.Example/Account');
  assert.equal(u.host, 'shop.example');
  assert.equal(u.path, '/Account');
});

test('parseQuery preserves order and duplicates', () => {
  const params = parseQuery('a=1&b=2&a=3');
  assert.deepEqual(
    params.map((p) => `${p.name}=${p.value}`),
    ['a=1', 'b=2', 'a=3'],
  );
});

test('parseQuery records semicolon-separated parameters', () => {
  const params = parseQuery('a=1;b=2');
  assert.equal(params.length, 2);
  assert.equal(params[0]?.semicolon, false);
  assert.equal(params[1]?.semicolon, true);
});

test('parseQuery keeps a valueless parameter', () => {
  const params = parseQuery('flagged&a=1');
  assert.equal(params[0]?.name, 'flagged');
  assert.equal(params[0]?.value, '');
});

test('canonicalQuery sorts by name then value', () => {
  assert.equal(canonicalQuery(parseQuery('b=2&a=1')), 'a=1&b=2');
  assert.equal(canonicalQuery(parseQuery('a=2&a=1')), 'a=1&a=2');
});

test('canonicalQuery makes two orderings of one query identical', () => {
  assert.equal(canonicalQuery(parseQuery('q=shoes&lang=en')), canonicalQuery(parseQuery('lang=en&q=shoes')));
});

test('serialiseQuery round-trips', () => {
  assert.equal(serialiseQuery(parseQuery('a=1&b=2')), 'a=1&b=2');
});

test('cacheVisibleExtension sees the suffix a by-extension rule would', () => {
  assert.equal(cacheVisibleExtension('/account.css'), 'css');
  assert.equal(cacheVisibleExtension('/a/b/app.min.js'), 'js');
  assert.equal(cacheVisibleExtension('/account'), null);
  assert.equal(cacheVisibleExtension('/.well-known/thing'), null);
  assert.equal(cacheVisibleExtension('/x.verylongextension'), null);
});

test('looksStaticToCache matches on extension and on prefix', () => {
  assert.equal(looksStaticToCache('/account.css').static, true);
  assert.equal(looksStaticToCache('/static/anything').static, true);
  assert.equal(looksStaticToCache('/_next/static/chunk').static, true);
  assert.equal(looksStaticToCache('/account').static, false);
  assert.ok(looksStaticToCache('/account.js').why.includes('.js'));
});

test('decodeOnce decodes a single layer and leaves NUL encoded', () => {
  assert.equal(decodeOnce('/static/..%2faccount'), '/static/../account');
  assert.equal(decodeOnce('/a%3Bb'), '/a;b');
  assert.equal(decodeOnce('/a%2500b'), '/a%00b');
  assert.equal(decodeOnce('/a%00b'), '/a%00b');
  assert.equal(decodeOnce('/a%zzb'), '/a%zzb');
});

test('resolveDotSegments resolves like a server-side router', () => {
  assert.equal(resolveDotSegments('/static/../account'), '/account');
  assert.equal(resolveDotSegments('/a/./b'), '/a/b');
  assert.equal(resolveDotSegments('/a//b'), '/a/b');
  assert.equal(resolveDotSegments('/a/b/'), '/a/b/');
  assert.equal(resolveDotSegments('/'), '/');
});

test('the delimiter matrix covers the nine documented sequences', () => {
  assert.deepEqual(
    DELIMITERS.map((d) => d.token),
    ['.', '/', '%2F', '//', ';', '%3B', '?', '%23', '..%2f'],
  );
  for (const d of DELIMITERS) {
    assert.ok(d.label.length > 0, `${d.token} needs a label`);
    assert.ok(d.why.length > 20, `${d.token} needs a mechanism`);
  }
});

test('delimiterSplits finds the base resource behind a suffix', () => {
  const splits = delimiterSplits('/account.css');
  assert.ok(splits.some((s) => s.delimiter.token === '.' && s.base === '/account' && s.suffix === 'css'));
});

test('delimiterSplits handles a semicolon path parameter', () => {
  const splits = delimiterSplits('/account;x.js');
  assert.ok(splits.some((s) => s.delimiter.token === ';' && s.base === '/account'));
});

test('delimiterSplits never returns an empty or root base', () => {
  for (const s of delimiterSplits('//a//b')) {
    assert.notEqual(s.base, '');
    assert.notEqual(s.base, '/');
  }
});

test('originCandidates strips a static extension', () => {
  const paths = originCandidates('/account.css').map((c) => c.path);
  assert.ok(paths.includes('/account'));
});

test('originCandidates escapes a static prefix via an encoded dot segment', () => {
  const found = originCandidates('/static/..%2faccount');
  const match = found.find((c) => c.path === '/account');
  assert.ok(match !== undefined, 'expected /account among the candidates');
  assert.deepEqual(match?.via, ['percent-decode', 'resolve-dot-segments']);
});

test('originCandidates strips path parameters', () => {
  assert.ok(originCandidates('/account;jsessionid=x').some((c) => c.path === '/account'));
});

test('originCandidates collapses doubled slashes', () => {
  assert.ok(originCandidates('//profile').some((c) => c.path === '/profile'));
});

test('originCandidates truncates at a decoded hash', () => {
  const paths = originCandidates('/account%23.css').map((c) => c.path);
  assert.ok(paths.includes('/account'));
});

test('originCandidates always includes the path itself with no transformations', () => {
  const self = originCandidates('/account').find((c) => c.path === '/account');
  assert.ok(self !== undefined);
  assert.deepEqual(self?.via, []);
});

test('originCandidates terminates and stays small', () => {
  const found = originCandidates('/static/..%2f..%2faccount;x%23.css');
  assert.ok(found.length > 1);
  assert.ok(found.length < 64, `candidate set grew to ${found.length}`);
});
