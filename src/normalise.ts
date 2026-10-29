/**
 * Body normalisation.
 *
 * Two responses to the same URL almost never match byte for byte. CSP nonces,
 * CSRF tokens, request ids, timestamps and build hashes all rotate per
 * response, and a diff that reports those as "the response varied" is noise
 * that buries the one difference that matters.
 *
 * Every normaliser is named, documented and listed in the report, so a reader
 * can see exactly what was masked before the comparison. The set is
 * configurable: `--normalisers <file>` adds rules, `--no-default-normalisers`
 * drops these, and `--list-normalisers` prints them.
 */

export interface Normaliser {
  readonly id: string;
  readonly description: string;
  readonly pattern: RegExp;
  /** Replacement text. Defaults to `<id>`. */
  readonly replacement?: string;
}

export const DEFAULT_NORMALISERS: readonly Normaliser[] = [
  {
    id: 'csp-nonce',
    description: 'nonce-<value> inside a Content-Security-Policy or a nonce= attribute',
    pattern: /\bnonce(?:-|="|='|=)[A-Za-z0-9+/_=-]{6,}("|')?/gi,
  },
  {
    id: 'csrf-meta',
    description: 'csrf/xsrf token carried in a meta tag attribute or a hidden form input',
    pattern:
      /((?:name|id)\s*=\s*["'][^"']*(?:csrf|xsrf|authenticity)[^"']*["'][^>]{0,160}?(?:content|value)\s*=\s*["'])[^"']{6,}/gi,
    replacement: '$1<csrf-meta>',
  },
  {
    id: 'csrf-token',
    description: 'csrf/xsrf/authenticity token in an attribute, JSON field or meta tag',
    pattern:
      /\b(?:csrf|xsrf|authenticity|request)[_-]?token["']?\s*[:=]\s*["']?[A-Za-z0-9+/_=.-]{8,}["']?/gi,
  },
  {
    id: 'iso-timestamp',
    description: 'ISO 8601 date-time, with or without fractional seconds and zone',
    pattern: /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?/g,
  },
  {
    id: 'http-date',
    description: 'RFC 9110 IMF-fixdate, as it appears in bodies that echo Date',
    pattern:
      /\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT\b/g,
  },
  {
    id: 'epoch-millis',
    description: '13-digit epoch milliseconds',
    pattern: /\b1[0-9]{12}\b/g,
  },
  {
    id: 'epoch-seconds',
    description: '10-digit epoch seconds',
    pattern: /\b1[0-9]{9}\b/g,
  },
  {
    id: 'uuid',
    description: 'RFC 9562 UUID in any version',
    pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
  },
  {
    id: 'build-hash-path',
    description: 'content-hash segment in a bundler asset path (/_next/static/<hash>/, /assets/<hash>/)',
    pattern: /\/(?:_next\/static|assets|build|static\/chunks)\/[A-Za-z0-9_-]{8,}\//g,
  },
  {
    id: 'build-hash-filename',
    description: 'content hash inside an asset filename (app.1f3a9c2b.js, main-9f8e7d6c.css)',
    pattern: /([A-Za-z0-9_]+)[.-][0-9a-f]{8,32}\.(js|css|mjs|map)\b/g,
    replacement: '$1.<build-hash-filename>.$2',
  },
  {
    id: 'cache-buster-query',
    description: 'cache-buster or version query parameter on an asset reference',
    pattern: /([?&](?:v|ver|version|t|ts|cb|_)=)[A-Za-z0-9._-]{1,40}/g,
    replacement: '$1<cache-buster-query>',
  },
  {
    id: 'request-id',
    description: 'request/trace/correlation id echoed into the body',
    pattern:
      /\b(?:request|trace|correlation|span|ray)[_-]?id["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{8,}["']?/gi,
  },
  {
    id: 'etag-literal',
    description: 'quoted entity tag echoed into the body',
    pattern: /\bW\/?"[A-Za-z0-9+/_=-]{8,}"/g,
  },
  {
    id: 'whitespace',
    description: 'runs of whitespace collapsed to one space, and leading/trailing trimmed',
    pattern: /\s+/g,
    replacement: ' ',
  },
];

export class NormaliserSet {
  readonly normalisers: readonly Normaliser[];

  constructor(normalisers: readonly Normaliser[]) {
    this.normalisers = normalisers;
  }

  static default(): NormaliserSet {
    return new NormaliserSet(DEFAULT_NORMALISERS);
  }

  ids(): string[] {
    return this.normalisers.map((n) => n.id);
  }

  /** Apply every normaliser in order. `null` bodies normalise to the empty string. */
  apply(body: string | null): string {
    let out = body ?? '';
    for (const n of this.normalisers) {
      const re = new RegExp(n.pattern.source, n.pattern.flags.includes('g') ? n.pattern.flags : `${n.pattern.flags}g`);
      out = out.replace(re, n.replacement ?? `<${n.id}>`);
    }
    return out.trim();
  }

  /** True when two bodies are indistinguishable once the noise is masked. */
  equivalent(a: string | null, b: string | null): boolean {
    return this.apply(a) === this.apply(b);
  }
}

/**
 * Parse a normaliser configuration file. The shape is deliberately narrow and
 * is validated field by field: capture files and config files are untrusted
 * input, and nothing here is ever evaluated as code.
 */
export function parseNormaliserConfig(raw: unknown, label: string): Normaliser[] {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error(`${label}: expected a JSON object with a "normalisers" array`);
  }
  const list = (raw as { normalisers?: unknown }).normalisers;
  if (!Array.isArray(list)) {
    throw new Error(`${label}: expected a JSON object with a "normalisers" array`);
  }
  return list.map((item, i) => {
    const at = `${label}: normalisers[${i}]`;
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      throw new Error(`${at}: expected an object`);
    }
    const o = item as Record<string, unknown>;
    const id = o['id'];
    const description = o['description'];
    const pattern = o['pattern'];
    const flags = o['flags'];
    const replacement = o['replacement'];
    if (typeof id !== 'string' || id === '') throw new Error(`${at}: "id" must be a non-empty string`);
    if (typeof pattern !== 'string' || pattern === '') {
      throw new Error(`${at}: "pattern" must be a non-empty string`);
    }
    if (description !== undefined && typeof description !== 'string') {
      throw new Error(`${at}: "description" must be a string`);
    }
    if (flags !== undefined && typeof flags !== 'string') {
      throw new Error(`${at}: "flags" must be a string`);
    }
    if (replacement !== undefined && typeof replacement !== 'string') {
      throw new Error(`${at}: "replacement" must be a string`);
    }
    const useFlags = flags === undefined ? 'g' : flags.includes('g') ? flags : `${flags}g`;
    let compiled: RegExp;
    try {
      compiled = new RegExp(pattern, useFlags);
    } catch (err) {
      throw new Error(`${at}: invalid regular expression: ${(err as Error).message}`);
    }
    const out: Normaliser = {
      id,
      description: typeof description === 'string' ? description : 'user-supplied normaliser',
      pattern: compiled,
      ...(replacement === undefined ? {} : { replacement }),
    };
    return out;
  });
}
