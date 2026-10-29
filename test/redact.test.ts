import assert from 'node:assert/strict';
import test from 'node:test';

import { analyse } from '../src/analyse.js';
import { formatReport } from '../src/format.js';
import { makeHeader } from '../src/headers.js';
import { REDACTED, Redactor } from '../src/redact.js';
import type { CaptureEntry, HeaderPair } from '../src/types.js';
import { exampleEntries } from './helpers.js';

/** Credential values that appear in the shipped fixtures. */
const FIXTURE_SECRETS = [
  'FIXTURE-USER-A',
  'FIXTURE-USER-B',
  'FIXTURE-USER-C',
  'FIXTURE-USER-D',
  'FIXTURE-TOKEN-A',
];

const ALL_EXAMPLES = [
  'unkeyed-x-forwarded-host.json',
  'css-suffix-deception.har',
  'clean-well-configured.json',
  'nonce-noise.json',
  'unkeyed-query-cookie-and-directives.json',
];

test('a Cookie header keeps its names and loses its values', () => {
  const r = new Redactor(true, ['FIXTURE-USER-A']);
  assert.equal(
    r.header(makeHeader('Cookie', 'session=FIXTURE-USER-A; theme=dark')),
    `session=${REDACTED}; theme=${REDACTED}`,
  );
});

test('a Set-Cookie header keeps its name and attributes', () => {
  const r = new Redactor(true, []);
  assert.equal(
    r.header(makeHeader('Set-Cookie', 'session=FIXTURE-USER-A; Path=/; HttpOnly')),
    `session=${REDACTED}; Path=/; HttpOnly`,
  );
});

test('an Authorization header keeps its scheme', () => {
  const r = new Redactor(true, []);
  assert.equal(r.header(makeHeader('Authorization', 'Bearer FIXTURE-TOKEN-A')), `Bearer ${REDACTED}`);
  assert.equal(r.header(makeHeader('Authorization', 'opaque-no-scheme')), REDACTED);
});

test('an API-key header is removed entirely', () => {
  const r = new Redactor(true, []);
  assert.equal(r.header(makeHeader('X-Api-Key', 'FIXTURE-TOKEN-A')), REDACTED);
  assert.equal(r.header(makeHeader('X-Csrf-Token', 'abc')), REDACTED);
});

test('a non-credential header is passed through', () => {
  const r = new Redactor(true, []);
  assert.equal(r.header(makeHeader('Accept', 'text/html')), 'text/html');
});

test('literal redaction removes a harvested value wherever it appears', () => {
  const r = new Redactor(true, ['FIXTURE-USER-A']);
  assert.equal(r.text('body echoed FIXTURE-USER-A twice: FIXTURE-USER-A'), `body echoed ${REDACTED} twice: ${REDACTED}`);
});

test('literal redaction ignores values too short to be credentials', () => {
  const r = new Redactor(true, ['ab']);
  assert.equal(r.text('ab cd'), 'ab cd');
});

test('longer literals are redacted before shorter overlapping ones', () => {
  const r = new Redactor(true, ['TOKEN', 'TOKEN-LONGER']);
  assert.equal(r.text('TOKEN-LONGER'), REDACTED);
});

test('bearer tokens and credential query parameters are redacted by pattern', () => {
  const r = new Redactor(true, []);
  assert.equal(r.text('Authorization: Bearer abcdefghij123456'), `Authorization: Bearer ${REDACTED}`);
  assert.equal(r.text('/cb?access_token=abcdefgh1234&x=1'), `/cb?access_token=${REDACTED}&x=1`);
  assert.equal(r.text('/cb?signature=abcdefgh1234'), `/cb?signature=${REDACTED}`);
});

test('a disabled redactor is a pass-through', () => {
  const r = Redactor.disabled();
  assert.equal(r.enabled, false);
  assert.equal(r.text('Bearer abcdefghij123456'), 'Bearer abcdefghij123456');
  assert.equal(r.header(makeHeader('Cookie', 'session=FIXTURE-USER-A')), 'session=FIXTURE-USER-A');
});

test('fromEntries harvests cookie, Authorization and query credentials', () => {
  const entries = exampleEntries('unkeyed-query-cookie-and-directives.json');
  const r = Redactor.fromEntries(entries, true);
  assert.equal(r.text('session=FIXTURE-USER-A'), `session=${REDACTED}`);
  assert.equal(r.text('token was FIXTURE-TOKEN-A'), `token was ${REDACTED}`);
});

test('no fixture credential survives into any output format, by default', () => {
  for (const format of ['text', 'json', 'markdown'] as const) {
    const report = analyse(exampleEntries(...ALL_EXAMPLES));
    const output = formatReport(report, format);
    assert.ok(output.length > 500, 'expected a substantial report');
    for (const secret of FIXTURE_SECRETS) {
      assert.equal(
        output.includes(secret),
        false,
        `${format} output leaked the fixture credential ${secret}`,
      );
    }
  }
});

test('the report records that redaction was applied', () => {
  assert.equal(analyse(exampleEntries(...ALL_EXAMPLES)).redacted, true);
});

test('cookie and header NAMES still reach the report, because findings need them', () => {
  const text = formatReport(analyse(exampleEntries('unkeyed-query-cookie-and-directives.json')), 'text');
  assert.ok(text.includes('cookie session'), 'the finding must name the cookie it varies with');
});

test('--no-redact genuinely disables redaction', () => {
  const report = analyse(exampleEntries('unkeyed-query-cookie-and-directives.json'), { redact: false });
  assert.equal(report.redacted, false);
  const text = formatReport(report, 'text');
  assert.ok(text.includes('REDACTION DISABLED'));
});

test('a credential in a URL-valued header reaches the literal set', () => {
  // Referer, Location and Content-Location are not credential headers -- they
  // are kept because they affect routing and caching -- so they were not
  // harvested, and a token that arrived only in one of them was absent from
  // the literal set. The same token echoed in a response body was then
  // rendered verbatim, while the identical token in `request.url` was
  // redacted. The fragment case is the sharp one: an OAuth implicit-flow
  // redirect puts `access_token` after the `#`, and that is what `Location`
  // carries.
  const TOKEN = 'URLHEADER-TOKEN-0123456789';
  const url = 'https://api.example.test/resource';
  const entry = (
    requestHeaders: HeaderPair[],
    responseHeaders: HeaderPair[],
  ): CaptureEntry => ({
    index: 1,
    source: 'unit.har',
    request: { method: 'GET', url, headers: requestHeaders, body: null },
    response: { status: 200, headers: responseHeaders, body: null },
  });

  const cases: [string, CaptureEntry][] = [
    ['Referer query', entry([makeHeader('Referer', `https://login.example.test/cb?access_token=${TOKEN}`)], [])],
    ['Location fragment', entry([], [makeHeader('Location', `https://app.example.test/cb#access_token=${TOKEN}`)])],
    ['Location query', entry([], [makeHeader('Location', `https://app.example.test/cb?id_token=${TOKEN}`)])],
    ['Content-Location query', entry([], [makeHeader('Content-Location', `https://app.example.test/r?api_key=${TOKEN}`)])],
  ];

  for (const [label, one] of cases) {
    const r = Redactor.fromEntries([one], true);
    assert.equal(r.text(`echoed back: ${TOKEN}`), `echoed back: ${REDACTED}`, label);
  }
});

test('a non-credential query parameter in a URL-valued header is not redacted', () => {
  // The harvest is driven by the parameter name, so an ordinary cache input
  // must survive it -- otherwise the tool would redact the very values it
  // exists to report on.
  const entry: CaptureEntry = {
    index: 1,
    source: 'unit.har',
    request: {
      method: 'GET',
      url: 'https://api.example.test/resource',
      headers: [makeHeader('Referer', 'https://login.example.test/cb?utm_campaign=SPRINGSALE2026X')],
      body: null,
    },
    response: { status: 200, headers: [], body: null },
  };
  const r = Redactor.fromEntries([entry], true);
  assert.equal(r.text('campaign SPRINGSALE2026X'), 'campaign SPRINGSALE2026X');
});
