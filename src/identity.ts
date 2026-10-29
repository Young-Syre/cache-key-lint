/**
 * "What identified the user?"
 *
 * The deception finding that is worth reporting is not "this URL could be
 * cached". It is "this response identified a user and a shared cache was
 * allowed to keep it", and a report is only actionable if it names the thing
 * that did the identifying. Everything in this module exists to produce that
 * sentence.
 */

import { headerValue, parseCookieHeader, parseVary, setCookieNames } from './headers.js';
import type { NormaliserSet } from './normalise.js';
import { requestAuth } from './policy.js';
import type { CaptureEntry } from './types.js';

export interface IdentitySignal {
  /** Short machine-ish label, e.g. `set-cookie`, `body-marker:email`. */
  readonly label: string;
  /** The sentence that goes in the report. */
  readonly detail: string;
  readonly strength: 'proof' | 'inference';
}

export interface BodyMarker {
  readonly id: string;
  readonly description: string;
  readonly pattern: RegExp;
}

/**
 * Markers that suggest a body is about one particular person. These are
 * heuristics and are reported as inferences; the proof-strength signals are
 * the ones derived from differing credentials producing differing bodies.
 */
export const IDENTITY_MARKERS: readonly BodyMarker[] = [
  {
    id: 'email-address',
    description: 'an e-mail address',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/,
  },
  {
    id: 'greeting',
    description: 'a personal greeting ("Signed in as", "Welcome back", "Hello,")',
    pattern: /\b(?:signed in as|logged in as|welcome back|hello),?\s+[A-Z][\w'’-]{1,40}/i,
  },
  {
    id: 'user-id-field',
    description: 'a user, account or customer identifier field',
    pattern: /"(?:user_?id|account_?id|customer_?id|member_?id)"\s*:\s*"?[\w-]{1,64}/i,
  },
  {
    id: 'user-attribute',
    description: 'a data-user attribute in the markup',
    pattern: /\bdata-user(?:-id|-name|-email)?\s*=\s*"[^"]{1,64}"/i,
  },
  {
    id: 'balance-or-order',
    description: 'an account balance, order number or invoice reference',
    pattern: /\b(?:balance|order[\s_-]?(?:no|number|id)|invoice[\s_-]?(?:no|number|id))\b[^\n]{0,24}[\d£$€]/i,
  },
  {
    id: 'logout-control',
    description: 'a sign-out control, which only an authenticated page carries',
    pattern: /(?:href|action)\s*=\s*"[^"]*\/(?:logout|sign[-_]?out|signout)\b/i,
  },
];

/**
 * All the reasons the capture gives for believing this response is about one
 * user. `siblings` are other entries for the same resource, used for the
 * differing-credentials comparison.
 */
export function identitySignals(
  entry: CaptureEntry,
  siblings: readonly CaptureEntry[],
  normalisers: NormaliserSet,
): IdentitySignal[] {
  const out: IdentitySignal[] = [];
  const setCookies = setCookieNames(entry.response.headers);
  if (setCookies.length > 0) {
    out.push({
      label: 'set-cookie',
      detail: `the response sets ${setCookies.length === 1 ? 'the cookie' : 'cookies'} ${setCookies.join(', ')}, so the stored body carries a session assignment`,
      strength: 'proof',
    });
  }

  const auth = requestAuth(entry.request);
  if (auth.authorizationHeader) {
    out.push({
      label: 'authorization-gated',
      detail: `the request that produced it carried an Authorization: ${auth.scheme ?? 'credential'} header`,
      strength: 'proof',
    });
  }
  if (auth.sessionCookies.length > 0) {
    out.push({
      label: 'session-cookie-gated',
      detail: `the request that produced it carried the session cookie ${auth.sessionCookies.join(', ')}`,
      strength: 'inference',
    });
  }

  if (parseVary(entry.response.headers).includes('cookie')) {
    out.push({
      label: 'vary-cookie',
      detail: 'the origin itself declares Vary: Cookie on this resource, so it considers the response cookie-dependent',
      strength: 'proof',
    });
  }

  // The strongest capture-derived signal: two credentials, two bodies.
  const cookiesHere = parseCookieHeader(entry.request.headers);
  for (const other of siblings) {
    if (other.index === entry.index) continue;
    const cookiesThere = parseCookieHeader(other.request.headers);
    const differing = [...cookiesHere.keys()].filter(
      (name) => cookiesThere.has(name) && cookiesThere.get(name) !== cookiesHere.get(name),
    );
    const authHere = headerValue(entry.request.headers, 'authorization');
    const authThere = headerValue(other.request.headers, 'authorization');
    const authDiffers = authHere !== null && authThere !== null && authHere !== authThere;
    if (differing.length === 0 && !authDiffers) continue;
    if (normalisers.equivalent(entry.response.body, other.response.body)) continue;
    const what = differing.length > 0 ? `the cookie ${differing.join(', ')}` : 'the Authorization header';
    out.push({
      label: 'credential-dependent-body',
      detail: `entries ${entry.index} and ${other.index} differ only in ${what} and returned different bodies, so the response content is per-user`,
      strength: 'proof',
    });
    break;
  }

  const body = entry.response.body ?? '';
  for (const marker of IDENTITY_MARKERS) {
    if (marker.pattern.test(body)) {
      out.push({
        label: `body-marker:${marker.id}`,
        detail: `the body contains ${marker.description}`,
        strength: 'inference',
      });
    }
  }

  return out;
}

export function isUserSpecific(signals: readonly IdentitySignal[]): boolean {
  return signals.length > 0;
}

export function hasProof(signals: readonly IdentitySignal[]): boolean {
  return signals.some((s) => s.strength === 'proof');
}

/** The sentence the deception findings lead with. */
export function describeIdentity(signals: readonly IdentitySignal[]): string {
  if (signals.length === 0) return 'nothing in the capture identifies a user';
  return signals.map((s) => s.detail).join('; ');
}
