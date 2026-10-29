import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import test from 'node:test';

import { ROOT, SRC, sourceFiles } from './helpers.js';

/**
 * The central promise of this tool is that it never touches the network. That
 * promise is only worth something if it is enforced, so this file fails the
 * build if any networking capability is imported or referenced anywhere in
 * src/.
 */
const FORBIDDEN_MODULES = [
  'http',
  'https',
  'http2',
  'net',
  'tls',
  'dns',
  'dgram',
  'cluster',
  'child_process',
  'worker_threads',
  'undici',
  'axios',
  'node-fetch',
  'got',
  'superagent',
  'request',
  'ws',
];

const FORBIDDEN_GLOBALS = [
  'fetch(',
  'XMLHttpRequest',
  'WebSocket',
  'EventSource',
  'navigator.sendBeacon',
  'import(',
  'eval(',
  'new Function(',
  'execSync',
  'spawnSync',
];

test('src/ imports no networking module', () => {
  const files = sourceFiles();
  assert.ok(files.length >= 12, `expected a real source tree, found ${files.length} files`);
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    const rel = relative(ROOT, file);
    for (const mod of FORBIDDEN_MODULES) {
      const patterns = [
        new RegExp(`from\\s+['"](?:node:)?${mod}['"]`),
        new RegExp(`require\\(\\s*['"](?:node:)?${mod}['"]`),
        new RegExp(`import\\s*\\(\\s*['"](?:node:)?${mod}['"]`),
      ];
      for (const p of patterns) {
        assert.equal(p.test(text), false, `${rel} must not import ${mod}`);
      }
    }
  }
});

test('src/ references no network or dynamic-evaluation global', () => {
  for (const file of sourceFiles()) {
    const text = readFileSync(file, 'utf8');
    const rel = relative(ROOT, file);
    for (const needle of FORBIDDEN_GLOBALS) {
      assert.equal(text.includes(needle), false, `${rel} must not reference ${needle}`);
    }
  }
});

test('only node:fs and node:path are imported from the standard library', () => {
  const allowed = new Set(['node:fs', 'node:path']);
  const seen = new Set<string>();
  for (const file of sourceFiles()) {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(/from\s+['"](node:[a-z_/]+)['"]/g)) {
      const mod = m[1] as string;
      seen.add(mod);
      assert.ok(allowed.has(mod), `unexpected standard-library import ${mod}`);
    }
  }
  assert.ok(seen.size <= allowed.size);
});

test('the package declares no runtime dependencies', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as Record<string, unknown>;
  assert.equal(pkg['dependencies'], undefined);
  assert.equal(pkg['peerDependencies'], undefined);
  assert.equal(pkg['optionalDependencies'], undefined);
  assert.deepEqual(Object.keys(pkg['devDependencies'] as object).sort(), ['@types/node', 'typescript']);
});

test('the declared version matches src/version.ts', async () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { version: string };
  const { VERSION } = await import('../src/version.js');
  assert.equal(VERSION, pkg.version);
});

test('no source file contains an absolute home-directory path', () => {
  for (const file of sourceFiles(SRC)) {
    const text = readFileSync(file, 'utf8');
    assert.equal(/\/home\/[a-z]/.test(text), false, `${file} leaks a local path`);
    assert.equal(/\/Users\/[a-z]/.test(text), false, `${file} leaks a local path`);
  }
});
