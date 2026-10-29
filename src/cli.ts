#!/usr/bin/env node
/**
 * Command line interface.
 *
 * Reads local files, writes local files, and does nothing else. There is no
 * network code anywhere in `src/` and a test asserts it stays that way.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';

import { analyse } from './analyse.js';
import { CaptureError, mergeCaptures, parseCapture, type LoadResult } from './capture.js';
import {
  formatCacheHeaders,
  formatDelimiters,
  formatNormalisers,
  formatPlan,
  formatReport,
  formatRules,
  severityCounts,
  type Format,
} from './format.js';
import { DEFAULT_NORMALISERS, NormaliserSet, parseNormaliserConfig } from './normalise.js';
import { buildPlan } from './plan.js';
import { SEVERITY_ORDER, severityAtLeast, type Severity } from './types.js';
import { TOOL, VERSION } from './version.js';

export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_USAGE = 2;
export const EXIT_INTERNAL = 3;

const FORMATS: readonly Format[] = ['text', 'json', 'markdown'];

export interface Io {
  readonly out: (text: string) => void;
  readonly err: (text: string) => void;
}

const HELP = `${TOOL} ${VERSION} — offline web-cache key inference and poisoning/deception linter

USAGE
  ${TOOL} <capture.har|capture.json> [more captures...] [options]
  ${TOOL} lint <capture...> [options]
  ${TOOL} plan <capture...> --url <url> [options]
  ${TOOL} rules [--format <fmt>]
  ${TOOL} delimiters [--format <fmt>]
  ${TOOL} cache-headers [--format <fmt>]
  ${TOOL} normalisers [--format <fmt>]

COMMANDS
  lint          Infer the cache key for every resource in the capture and report
                unkeyed-input and cache-deception findings. The default command.
  plan          Emit the request matrix a tester should send to resolve the key
                for one URL, with a cache-buster on every probe.
  rules         Print the rule catalogue (ID, name, severity, mechanism).
  delimiters    Print the path-delimiter matrix and why each one works.
  cache-headers Print the cache-status headers the tool reads as evidence.
  normalisers   Print the body normalisers applied before any comparison.

OPTIONS
  --format <text|json|markdown>   Output format. Default text.
  --fail-on <severity|never>      Exit 1 when a finding of this severity or worse
                                  is reported. One of ${SEVERITY_ORDER.join(', ')}, or
                                  never. Default medium.
  -o, --out <file>                Write the output to a file instead of stdout.
  --no-redact                     Print credential values verbatim. Off by default:
                                  captures of authenticated sessions are credential
                                  stores, and reports get pasted into tickets.
  --normalisers <file>            Add body normalisers from a JSON file
                                  ({"normalisers":[{"id","pattern","flags","replacement"}]}).
  --no-default-normalisers        Drop the built-in normaliser set.
  --url <url>                     plan: the URL to build the matrix for. Required.
  --buster <prefix>               plan: cache-buster token prefix. Default ckl.
  --quiet                         Do not print capture parse warnings.
  -h, --help                      This text.
  -V, --version                   Print the version.

EXIT CODES
  0  analysis completed and no finding reached --fail-on
  1  analysis completed and at least one finding reached --fail-on
  2  usage error, or a capture that could not be read or parsed
  3  an unexpected internal error

NETWORK
  None. This tool never resolves a name or opens a socket. Captures are treated
  as untrusted data: nothing in them is evaluated, and no URL in them is fetched.
`;

interface ParsedArgs {
  readonly command:
    | 'lint'
    | 'plan'
    | 'rules'
    | 'delimiters'
    | 'cache-headers'
    | 'normalisers'
    | 'help'
    | 'version';
  readonly files: readonly string[];
  readonly format: Format;
  readonly failOn: Severity | 'never';
  readonly out: string | null;
  readonly redact: boolean;
  readonly normaliserFile: string | null;
  readonly useDefaults: boolean;
  readonly url: string | null;
  readonly buster: string | null;
  readonly quiet: boolean;
}

class UsageError extends Error {}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  let command: ParsedArgs['command'] = 'lint';
  const files: string[] = [];
  let format: Format = 'text';
  let failOn: Severity | 'never' = 'medium';
  let out: string | null = null;
  let redact = true;
  let normaliserFile: string | null = null;
  let useDefaults = true;
  let url: string | null = null;
  let buster: string | null = null;
  let quiet = false;

  const rest = [...argv];
  const first = rest[0];
  if (first !== undefined && !first.startsWith('-')) {
    if (
      first === 'lint' ||
      first === 'plan' ||
      first === 'rules' ||
      first === 'delimiters' ||
      first === 'cache-headers' ||
      first === 'normalisers'
    ) {
      command = first;
      rest.shift();
    }
  }

  const need = (flag: string, value: string | undefined): string => {
    if (value === undefined) throw new UsageError(`${flag} requires a value`);
    return value;
  };

  while (rest.length > 0) {
    const arg = rest.shift() as string;
    switch (arg) {
      case '-h':
      case '--help':
        return { ...blank(), command: 'help' };
      case '-V':
      case '--version':
        return { ...blank(), command: 'version' };
      case '--format': {
        const value = need('--format', rest.shift());
        if (!FORMATS.includes(value as Format)) {
          throw new UsageError(`--format must be one of ${FORMATS.join(', ')} (got ${value})`);
        }
        format = value as Format;
        break;
      }
      case '--fail-on': {
        const value = need('--fail-on', rest.shift());
        if (value !== 'never' && !SEVERITY_ORDER.includes(value as Severity)) {
          throw new UsageError(`--fail-on must be one of ${SEVERITY_ORDER.join(', ')} or never (got ${value})`);
        }
        failOn = value as Severity | 'never';
        break;
      }
      case '-o':
      case '--out':
        out = need(arg, rest.shift());
        break;
      case '--no-redact':
        redact = false;
        break;
      case '--normalisers':
        normaliserFile = need('--normalisers', rest.shift());
        break;
      case '--no-default-normalisers':
        useDefaults = false;
        break;
      case '--url':
        url = need('--url', rest.shift());
        break;
      case '--buster':
        buster = need('--buster', rest.shift());
        break;
      case '--quiet':
        quiet = true;
        break;
      default:
        if (arg.startsWith('-')) throw new UsageError(`unknown option ${arg}`);
        files.push(arg);
    }
  }

  return { command, files, format, failOn, out, redact, normaliserFile, useDefaults, url, buster, quiet };
}

function blank(): ParsedArgs {
  return {
    command: 'lint',
    files: [],
    format: 'text',
    failOn: 'medium',
    out: null,
    redact: true,
    normaliserFile: null,
    useDefaults: true,
    url: null,
    buster: null,
    quiet: false,
  };
}

function buildNormalisers(args: ParsedArgs): NormaliserSet {
  const list = args.useDefaults ? [...DEFAULT_NORMALISERS] : [];
  if (args.normaliserFile !== null) {
    const label = basename(args.normaliserFile);
    const text = readFileSync(args.normaliserFile, 'utf8');
    let raw: unknown;
    try {
      raw = JSON.parse(text) as unknown;
    } catch (err) {
      throw new UsageError(`${label}: not valid JSON: ${(err as Error).message}`);
    }
    list.push(...parseNormaliserConfig(raw, label));
  }
  return new NormaliserSet(list);
}

function loadAll(files: readonly string[]): LoadResult[] {
  if (files.length === 0) throw new UsageError('no capture file given (see --help)');
  return files.map((file) => {
    const label = basename(file);
    let text: string;
    try {
      text = readFileSync(file, 'utf8');
    } catch (err) {
      throw new UsageError(`cannot read ${label}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`);
    }
    return parseCapture(text, label);
  });
}

function emit(text: string, args: ParsedArgs, io: Io): void {
  if (args.out === null) {
    io.out(text);
    return;
  }
  writeFileSync(args.out, `${text}\n`, 'utf8');
  io.err(`written to ${basename(args.out)}`);
}

export function run(argv: readonly string[], io: Io): number {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    io.err(`${TOOL}: ${(err as Error).message}`);
    return EXIT_USAGE;
  }

  try {
    switch (args.command) {
      case 'help':
        io.out(HELP.trimEnd());
        return EXIT_OK;
      case 'version':
        io.out(VERSION);
        return EXIT_OK;
      case 'rules':
        emit(formatRules(args.format), args, io);
        return EXIT_OK;
      case 'delimiters':
        emit(formatDelimiters(args.format), args, io);
        return EXIT_OK;
      case 'cache-headers':
        emit(formatCacheHeaders(args.format), args, io);
        return EXIT_OK;
      case 'normalisers':
        emit(
          formatNormalisers(
            buildNormalisers(args).normalisers.map((n) => ({ id: n.id, description: n.description })),
            args.format,
          ),
          args,
          io,
        );
        return EXIT_OK;
      case 'plan': {
        if (args.url === null) throw new UsageError('plan requires --url');
        const loaded = args.files.length === 0 ? [] : loadAll(args.files);
        const merged = mergeCaptures(loaded);
        if (!args.quiet) for (const w of merged.warnings) io.err(`warning: ${w}`);
        const plan = buildPlan(args.url, merged.entries, args.buster === null ? {} : { buster: args.buster });
        emit(formatPlan(plan, args.format), args, io);
        return EXIT_OK;
      }
      case 'lint': {
        const loaded = loadAll(args.files);
        const merged = mergeCaptures(loaded);
        if (!args.quiet) for (const w of merged.warnings) io.err(`warning: ${w}`);
        const report = analyse(merged.entries, {
          normalisers: buildNormalisers(args),
          redact: args.redact,
          captureLabels: merged.labels,
        });
        emit(formatReport(report, args.format), args, io);
        if (args.failOn === 'never') return EXIT_OK;
        const threshold = args.failOn;
        const counts = severityCounts(report.findings);
        const tripped = SEVERITY_ORDER.filter((s) => severityAtLeast(s, threshold)).some((s) => counts[s] > 0);
        return tripped ? EXIT_FINDINGS : EXIT_OK;
      }
      default:
        io.err(`${TOOL}: unknown command`);
        return EXIT_USAGE;
    }
  } catch (err) {
    if (err instanceof UsageError || err instanceof CaptureError) {
      io.err(`${TOOL}: ${err.message}`);
      return EXIT_USAGE;
    }
    io.err(`${TOOL}: internal error: ${(err as Error).message}`);
    return EXIT_INTERNAL;
  }
}

/* c8 ignore start */
const invokedDirectly =
  process.argv[1] !== undefined && process.argv[1].endsWith('cli.js');
if (invokedDirectly) {
  const code = run(process.argv.slice(2), {
    out: (text) => process.stdout.write(`${text}\n`),
    err: (text) => process.stderr.write(`${text}\n`),
  });
  process.exitCode = code;
}
/* c8 ignore stop */
