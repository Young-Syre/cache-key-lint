/**
 * Capture loading.
 *
 * Input is local capture data only: a HAR 1.2 file exported from a browser or
 * an intercepting proxy, or the small native format described in the README.
 * Captures are untrusted data. Nothing here evaluates code, resolves a URL, or
 * reads a file the capture names — every field is validated and coerced, and a
 * malformed entry is skipped with a warning rather than aborting the run.
 */

import type { Capture, CaptureEntry, CapturedRequest, CapturedResponse, HeaderPair } from './types.js';
import { makeHeader } from './headers.js';

export interface LoadResult {
  readonly capture: Capture;
  readonly warnings: readonly string[];
}

export class CaptureError extends Error {}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

/**
 * Accept the three header spellings seen in the wild: a HAR name/value array,
 * a plain object, and an array of two-element tuples.
 */
function readHeaders(value: unknown, where: string, warnings: string[]): HeaderPair[] {
  const out: HeaderPair[] = [];
  if (value === undefined || value === null) return out;
  if (Array.isArray(value)) {
    for (const item of value) {
      if (Array.isArray(item) && item.length >= 2) {
        const name = asString(item[0]);
        const v = item[1];
        if (name !== null) out.push(makeHeader(name, typeof v === 'string' ? v : String(v)));
        continue;
      }
      const rec = asRecord(item);
      if (rec === null) continue;
      const name = asString(rec['name']);
      if (name === null) continue;
      // HAR 1.2 allows pseudo-headers from HTTP/2; they are not cache inputs.
      if (name.startsWith(':')) continue;
      const v = rec['value'];
      out.push(makeHeader(name, typeof v === 'string' ? v : v === undefined || v === null ? '' : String(v)));
    }
    return out;
  }
  const rec = asRecord(value);
  if (rec === null) {
    warnings.push(`${where}: headers were neither an array nor an object; ignored`);
    return out;
  }
  for (const [name, v] of Object.entries(rec)) {
    if (name.startsWith(':')) continue;
    if (Array.isArray(v)) {
      for (const one of v) out.push(makeHeader(name, typeof one === 'string' ? one : String(one)));
      continue;
    }
    out.push(makeHeader(name, typeof v === 'string' ? v : v === undefined || v === null ? '' : String(v)));
  }
  return out;
}

/** HAR records cookies separately from the header; fold them in when the header is missing. */
function foldCookieList(headers: HeaderPair[], cookies: unknown, headerName: string): HeaderPair[] {
  const want = headerName.toLowerCase();
  if (headers.some((h) => h.lower === want)) return headers;
  if (!Array.isArray(cookies) || cookies.length === 0) return headers;
  const pairs: string[] = [];
  for (const item of cookies) {
    const rec = asRecord(item);
    if (rec === null) continue;
    const name = asString(rec['name']);
    if (name === null) continue;
    const v = asString(rec['value']) ?? '';
    pairs.push(`${name}=${v}`);
  }
  if (pairs.length === 0) return headers;
  if (want === 'set-cookie') {
    return [...headers, ...pairs.map((p) => makeHeader('Set-Cookie', p))];
  }
  return [...headers, makeHeader('Cookie', pairs.join('; '))];
}

function readBody(container: unknown, where: string, warnings: string[]): string | null {
  const rec = asRecord(container);
  if (rec === null) return null;
  const text = rec['text'];
  if (typeof text !== 'string') return null;
  const encoding = asString(rec['encoding']);
  if (encoding !== null && encoding.toLowerCase() === 'base64') {
    try {
      return Buffer.from(text, 'base64').toString('utf8');
    } catch {
      warnings.push(`${where}: body declared base64 but did not decode; used verbatim`);
      return text;
    }
  }
  return text;
}

function readRequest(value: unknown, where: string, warnings: string[]): CapturedRequest | null {
  const rec = asRecord(value);
  if (rec === null) return null;
  const url = asString(rec['url']);
  if (url === null || url === '') {
    warnings.push(`${where}: request has no url; entry skipped`);
    return null;
  }
  const method = (asString(rec['method']) ?? 'GET').toUpperCase();
  let headers = readHeaders(rec['headers'], `${where}.request`, warnings);
  headers = foldCookieList(headers, rec['cookies'], 'cookie');
  const body = rec['body'] !== undefined
    ? typeof rec['body'] === 'string'
      ? (rec['body'] as string)
      : readBody(rec['body'], `${where}.request`, warnings)
    : readBody(rec['postData'], `${where}.request`, warnings);
  return { method, url, headers, body };
}

function readResponse(value: unknown, where: string, warnings: string[]): CapturedResponse | null {
  const rec = asRecord(value);
  if (rec === null) return null;
  const rawStatus = rec['status'];
  const status = typeof rawStatus === 'number' ? rawStatus : Number.parseInt(String(rawStatus ?? ''), 10);
  if (!Number.isFinite(status)) {
    warnings.push(`${where}: response has no numeric status; entry skipped`);
    return null;
  }
  let headers = readHeaders(rec['headers'], `${where}.response`, warnings);
  headers = foldCookieList(headers, rec['cookies'], 'set-cookie');
  const body = rec['body'] !== undefined
    ? typeof rec['body'] === 'string'
      ? (rec['body'] as string)
      : readBody(rec['body'], `${where}.response`, warnings)
    : readBody(rec['content'], `${where}.response`, warnings);
  return { status, headers, body };
}

/**
 * Parse already-read capture text. `label` is used in report output, so pass a
 * basename — never a filesystem path.
 */
export function parseCapture(text: string, label: string, startIndex = 1): LoadResult {
  const warnings: string[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (err) {
    throw new CaptureError(`${label}: not valid JSON: ${(err as Error).message}`);
  }
  const root = asRecord(parsed);
  if (root === null) throw new CaptureError(`${label}: top level must be a JSON object`);

  let rawEntries: unknown;
  let format: 'har' | 'ckl';
  const log = asRecord(root['log']);
  if (log !== null && Array.isArray(log['entries'])) {
    rawEntries = log['entries'];
    format = 'har';
  } else if (Array.isArray(root['entries'])) {
    rawEntries = root['entries'];
    format = 'ckl';
  } else {
    throw new CaptureError(
      `${label}: expected a HAR file ("log.entries") or a native capture ("entries")`,
    );
  }

  const entries: CaptureEntry[] = [];
  let index = startIndex;
  for (const [i, raw] of (rawEntries as unknown[]).entries()) {
    const where = `${label}: entry ${i + 1}`;
    const rec = asRecord(raw);
    if (rec === null) {
      warnings.push(`${where}: not an object; skipped`);
      continue;
    }
    const request = readRequest(rec['request'], where, warnings);
    const response = readResponse(rec['response'], where, warnings);
    if (request === null || response === null) continue;
    entries.push({ index, source: label, request, response });
    index += 1;
  }
  if (entries.length === 0) {
    throw new CaptureError(`${label}: no usable entries (need at least one request/response pair)`);
  }
  const captureLabel = asString(root['label']) ?? label;
  return { capture: { label: captureLabel, format, entries }, warnings };
}

/** Merge several captures into one entry list, renumbering as it goes. */
export function mergeCaptures(results: readonly LoadResult[]): {
  entries: CaptureEntry[];
  labels: string[];
  warnings: string[];
} {
  const entries: CaptureEntry[] = [];
  const labels: string[] = [];
  const warnings: string[] = [];
  for (const r of results) {
    labels.push(r.capture.label);
    warnings.push(...r.warnings);
    for (const e of r.capture.entries) {
      entries.push({ ...e, index: entries.length + 1 });
    }
  }
  return { entries, labels, warnings };
}
