import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { CaptureError, mergeCaptures, parseCapture } from '../src/capture.js';
import { headerValue, parseCookieHeader, setCookieNames } from '../src/headers.js';
import { EXAMPLES } from './helpers.js';

const native = JSON.stringify({
  label: 'tiny',
  entries: [
    {
      request: { method: 'get', url: 'https://a.example/x', headers: { 'X-Test': 'one' } },
      response: { status: 200, headers: { 'Cache-Control': 'public' }, body: 'hello' },
    },
  ],
});

test('a HAR file is recognised and parsed', () => {
  const text = readFileSync(join(EXAMPLES, 'css-suffix-deception.har'), 'utf8');
  const { capture } = parseCapture(text, 'css-suffix-deception.har');
  assert.equal(capture.format, 'har');
  assert.equal(capture.entries.length, 4);
  assert.equal(capture.entries[0]?.request.method, 'GET');
  assert.equal(capture.entries[0]?.response.status, 200);
});

test('the native format is recognised and the method is upper-cased', () => {
  const { capture } = parseCapture(native, 'tiny.json');
  assert.equal(capture.format, 'ckl');
  assert.equal(capture.label, 'tiny');
  assert.equal(capture.entries[0]?.request.method, 'GET');
  assert.equal(headerValue(capture.entries[0]?.request.headers ?? [], 'x-test'), 'one');
});

test('headers are accepted as an object, a name/value array and tuples', () => {
  const asArray = parseCapture(
    JSON.stringify({
      entries: [
        {
          request: { url: '/a', headers: [{ name: 'A', value: '1' }] },
          response: { status: 200, headers: [['B', '2']] },
        },
      ],
    }),
    'f.json',
  ).capture.entries[0];
  assert.equal(headerValue(asArray?.request.headers ?? [], 'a'), '1');
  assert.equal(headerValue(asArray?.response.headers ?? [], 'b'), '2');
});

test('HTTP/2 pseudo-headers are dropped: they are not cache inputs', () => {
  const { capture } = parseCapture(
    JSON.stringify({
      entries: [
        {
          request: { url: '/a', headers: [{ name: ':method', value: 'GET' }, { name: 'X', value: '1' }] },
          response: { status: 200, headers: [] },
        },
      ],
    }),
    'f.json',
  );
  assert.deepEqual(
    capture.entries[0]?.request.headers.map((h) => h.name),
    ['X'],
  );
});

test('a HAR cookies array is folded into a Cookie header when none is present', () => {
  const { capture } = parseCapture(
    JSON.stringify({
      log: {
        entries: [
          {
            request: { url: '/a', method: 'GET', headers: [], cookies: [{ name: 'session', value: 'FIXTURE' }] },
            response: { status: 200, headers: [], cookies: [{ name: 'csrf', value: 'TOKEN' }] },
          },
        ],
      },
    }),
    'f.har',
  );
  const entry = capture.entries[0];
  assert.equal(parseCookieHeader(entry?.request.headers ?? []).get('session'), 'FIXTURE');
  assert.deepEqual(setCookieNames(entry?.response.headers ?? []), ['csrf']);
});

test('an existing Cookie header is not duplicated by the cookies array', () => {
  const { capture } = parseCapture(
    JSON.stringify({
      entries: [
        {
          request: { url: '/a', headers: [{ name: 'Cookie', value: 'a=1' }], cookies: [{ name: 'b', value: '2' }] },
          response: { status: 200, headers: [] },
        },
      ],
    }),
    'f.json',
  );
  const cookies = parseCookieHeader(capture.entries[0]?.request.headers ?? []);
  assert.equal(cookies.size, 1);
  assert.equal(cookies.get('a'), '1');
});

test('a base64 response body is decoded', () => {
  const { capture } = parseCapture(
    JSON.stringify({
      entries: [
        {
          request: { url: '/a', headers: [] },
          response: { status: 200, headers: [], content: { encoding: 'base64', text: 'aGVsbG8=' } },
        },
      ],
    }),
    'f.json',
  );
  assert.equal(capture.entries[0]?.response.body, 'hello');
});

test('a HAR postData body is read', () => {
  const { capture } = parseCapture(
    JSON.stringify({
      log: {
        entries: [
          {
            request: { url: '/a', method: 'GET', headers: [], postData: { text: 'q=1' } },
            response: { status: 200, headers: [] },
          },
        ],
      },
    }),
    'f.har',
  );
  assert.equal(capture.entries[0]?.request.body, 'q=1');
});

test('a string status is coerced', () => {
  const { capture } = parseCapture(
    JSON.stringify({ entries: [{ request: { url: '/a' }, response: { status: '301' } }] }),
    'f.json',
  );
  assert.equal(capture.entries[0]?.response.status, 301);
});

test('an entry with no URL is skipped and warned about', () => {
  const { capture, warnings } = parseCapture(
    JSON.stringify({
      entries: [
        { request: {}, response: { status: 200 } },
        { request: { url: '/ok' }, response: { status: 200 } },
      ],
    }),
    'f.json',
  );
  assert.equal(capture.entries.length, 1);
  assert.ok(warnings.some((w) => w.includes('no url')));
});

test('an entry with no numeric status is skipped and warned about', () => {
  const { capture, warnings } = parseCapture(
    JSON.stringify({
      entries: [
        { request: { url: '/a' }, response: { status: 'teapot' } },
        { request: { url: '/ok' }, response: { status: 200 } },
      ],
    }),
    'f.json',
  );
  assert.equal(capture.entries.length, 1);
  assert.ok(warnings.some((w) => w.includes('numeric status')));
});

test('invalid JSON, a non-object root and an unknown shape all raise CaptureError', () => {
  assert.throws(() => parseCapture('{', 'f.json'), CaptureError);
  assert.throws(() => parseCapture('[]', 'f.json'), /top level must be a JSON object/);
  assert.throws(() => parseCapture('{"x":1}', 'f.json'), /expected a HAR file/);
  assert.throws(() => parseCapture('{"entries":[]}', 'f.json'), /no usable entries/);
});

test('entry indices are 1-based and contiguous across merged captures', () => {
  const a = parseCapture(native, 'a.json');
  const b = parseCapture(native, 'b.json');
  const merged = mergeCaptures([a, b]);
  assert.deepEqual(
    merged.entries.map((e) => e.index),
    [1, 2],
  );
  assert.deepEqual(merged.labels, ['tiny', 'tiny']);
  assert.deepEqual(
    merged.entries.map((e) => e.source),
    ['a.json', 'b.json'],
  );
});

test('every shipped example parses', () => {
  for (const name of [
    'unkeyed-x-forwarded-host.json',
    'css-suffix-deception.har',
    'clean-well-configured.json',
    'nonce-noise.json',
    'unkeyed-query-cookie-and-directives.json',
  ]) {
    const { capture } = parseCapture(readFileSync(join(EXAMPLES, name), 'utf8'), name);
    assert.ok(capture.entries.length > 0, `${name} parsed to no entries`);
  }
});
