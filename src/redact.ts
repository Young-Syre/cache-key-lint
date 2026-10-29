/**
 * Redaction.
 *
 * A capture of an authenticated session is a credential store. The findings
 * this tool produces are about *which* cookie or header mattered, never about
 * its value, so values are removed by default and the names are kept — that is
 * precisely the information a report needs.
 *
 * Two mechanisms run together. Pattern redaction catches the usual shapes.
 * Literal redaction collects every credential value seen anywhere in the
 * loaded captures and strips those exact strings from all output, which is
 * what makes the guarantee hold even when a token has been echoed into a
 * response body or a URL.
 */

import { CREDENTIAL_HEADERS } from './headers.js';
import type { CaptureEntry, HeaderPair } from './types.js';

export const REDACTED = '<redacted>';

/**
 * Headers whose value is a URL, so its query and fragment are harvested for
 * credentials. These are not credential headers themselves -- they are kept
 * in a report because they affect routing and caching -- which is why they
 * have to be listed separately from CREDENTIAL_HEADERS.
 */
export const URL_VALUED_HEADERS: readonly string[] = ['referer', 'location', 'content-location'];

/** Query parameters whose value is a credential rather than a cache input. */
export const CREDENTIAL_QUERY_PARAMS: readonly string[] = [
  'access_token',
  'id_token',
  'refresh_token',
  'token',
  'auth',
  'apikey',
  'api_key',
  'key',
  'secret',
  'password',
  'passwd',
  'pwd',
  'signature',
  'sig',
  'x-amz-signature',
  'code',
  'session',
  'sessionid',
  'sid',
  'jwt',
];

const MIN_LITERAL = 4;

function cookiePairs(value: string): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  for (const part of value.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    out.push({ name: part.slice(0, eq).trim(), value: part.slice(eq + 1).trim() });
  }
  return out;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export class Redactor {
  readonly enabled: boolean;
  private readonly literals: string[];

  constructor(enabled: boolean, literals: Iterable<string>) {
    this.enabled = enabled;
    this.literals = [...new Set([...literals].filter((l) => l.length >= MIN_LITERAL))].sort(
      (a, b) => b.length - a.length,
    );
  }

  static disabled(): Redactor {
    return new Redactor(false, []);
  }

  /** Harvest every credential value present in the captures. */
  static fromEntries(entries: readonly CaptureEntry[], enabled: boolean): Redactor {
    const literals = new Set<string>();
    const add = (v: string): void => {
      const t = v.trim();
      if (t !== '') literals.add(t);
    };
    // A URL's query *and* fragment. The fragment matters because an OAuth
    // implicit-flow redirect puts `access_token` after the `#`, and that is
    // exactly what a captured `Location` header carries.
    const addFromUrl = (url: string): void => {
      const start = url.search(/[?#]/);
      if (start === -1) return;
      for (const part of url.slice(start + 1).split(/[&;?#]/)) {
        const eq = part.indexOf('=');
        if (eq <= 0) continue;
        if (!CREDENTIAL_QUERY_PARAMS.includes(part.slice(0, eq).toLowerCase())) continue;
        add(decodeURIComponent(part.slice(eq + 1)));
        add(part.slice(eq + 1));
      }
    };
    for (const e of entries) {
      for (const h of [...e.request.headers, ...e.response.headers]) {
        // Harvested before the credential-header test, not inside it: these
        // headers are not credentials, they are URLs that carry one. A token
        // in a `Referer` used to reach the literal set from nowhere, so the
        // same value echoed in a response body was rendered verbatim even
        // though the identical token in `request.url` was redacted.
        if (URL_VALUED_HEADERS.includes(h.lower)) addFromUrl(h.value);
        if (!CREDENTIAL_HEADERS.includes(h.lower)) continue;
        if (h.lower === 'cookie' || h.lower === 'set-cookie') {
          for (const p of cookiePairs(h.value)) add(p.value);
          continue;
        }
        if (h.lower === 'authorization' || h.lower === 'proxy-authorization' || h.lower === 'authentication') {
          const space = h.value.indexOf(' ');
          add(space === -1 ? h.value : h.value.slice(space + 1));
          continue;
        }
        add(h.value);
      }
      addFromUrl(e.request.url);
    }
    return new Redactor(enabled, literals);
  }

  /** The display form of a header value. */
  header(pair: HeaderPair): string {
    if (!this.enabled) return pair.value;
    if (pair.lower === 'cookie') {
      const pairs = cookiePairs(pair.value);
      if (pairs.length === 0) return REDACTED;
      return pairs.map((p) => `${p.name}=${REDACTED}`).join('; ');
    }
    if (pair.lower === 'set-cookie') {
      const eq = pair.value.indexOf('=');
      if (eq <= 0) return REDACTED;
      const semi = pair.value.indexOf(';');
      const attrs = semi === -1 ? '' : pair.value.slice(semi);
      return `${pair.value.slice(0, eq)}=${REDACTED}${attrs}`;
    }
    if (
      pair.lower === 'authorization' ||
      pair.lower === 'proxy-authorization' ||
      pair.lower === 'authentication'
    ) {
      const space = pair.value.indexOf(' ');
      if (space === -1) return REDACTED;
      return `${pair.value.slice(0, space)} ${REDACTED}`;
    }
    if (CREDENTIAL_HEADERS.includes(pair.lower)) return REDACTED;
    return this.text(pair.value);
  }

  /** Scrub any free text that is about to be printed. */
  text(input: string): string {
    if (!this.enabled) return input;
    let out = input;
    for (const literal of this.literals) {
      out = out.split(literal).join(REDACTED);
    }
    // Bearer/Basic tokens and credential query parameters, in case a value was
    // never seen as a header and so is not in the literal set.
    out = out.replace(/\b(Bearer|Basic|Digest|Token)\s+[A-Za-z0-9._~+/=-]{8,}/gi, `$1 ${REDACTED}`);
    for (const name of CREDENTIAL_QUERY_PARAMS) {
      out = out.replace(
        new RegExp(`([?&;]${escapeRe(name)}=)[^&;\\s"']{4,}`, 'gi'),
        `$1${REDACTED}`,
      );
    }
    return out;
  }

  /** Convenience: redact an array of headers into printable `name: value` lines. */
  lines(headers: readonly HeaderPair[]): string[] {
    return headers.map((h) => `${h.name}: ${this.header(h)}`);
  }
}
