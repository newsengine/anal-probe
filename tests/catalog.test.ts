/**
 * Catalog is the single source of truth for "every test we run". These tests make it impossible for
 * the catalog to silently drift from the engine:
 *  - no orphan finding ids: everything the scanner emits must be listed in the catalog
 *  - docs/CHECKS.md must be the freshly-generated render of the catalog (run `npm run catalog`)
 *  - catalog ids are unique
 *
 * Imports dist/ so we test the shipped build (`npm test` builds first).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { probe } from '../dist/probe.js';
import { CATALOG, catalogEntryFor, renderCatalogMarkdown, vtaNumber, vtaCode, assignNumbers } from '../dist/catalog.js';
import { CATALOG_NUMBERS } from '../dist/catalog-numbers.js';
import { SECRET_RULES } from '../dist/core.js';
import { startKnownBad, startKnownGood } from './helpers/fixtures.ts';
import type { Finding } from '../dist/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CHECKS_MD = join(__dirname, '..', 'docs', 'CHECKS.md');

// Offline-safe categories (dns/host need real network/DNS and are excluded here).
const OFFLINE_CATEGORIES = [
  'security', 'secrets', 'exposure', 'reliability', 'seo', 'a11y', 'performance',
  'components', 'agent', 'framework', 'appstyle', 'atlas', 'plugins',
] as const;

async function collectIds(url: string): Promise<Finding[]> {
  return probe(url, {
    only: [...OFFLINE_CATEGORIES] as any,
    // Turn on the opt-in probes so their dynamic families are exercised for catalog coverage.
    apiWrite: true,
    rateLimitScan: true,
    reflectedXss: true,
    maxCrawl: 10,
    timeoutMs: 8000,
  });
}

test('catalog: no orphan finding ids (every emitted id is catalogued)', async () => {
  const bad = await startKnownBad();
  const good = await startKnownGood();
  let findings: Finding[] = [];
  try {
    findings = [...await collectIds(bad.url), ...await collectIds(good.url)];
  } finally {
    await bad.close();
    await good.close();
  }

  const orphans = new Set<string>();
  for (const f of findings) {
    if (f.id.endsWith('.error')) continue; // per-category crash sentinel from probe(), not a real check
    if (!catalogEntryFor(f.id)) orphans.add(f.id);
  }
  assert.equal(
    orphans.size,
    0,
    `finding ids not in src/catalog.ts (add them, then \`npm run catalog\`):\n  ${[...orphans].join('\n  ')}`,
  );
});

test('catalog: the new #24 API families actually fire and are catalogued', async () => {
  const bad = await startKnownBad();
  let findings: Finding[] = [];
  try {
    findings = await collectIds(bad.url);
  } finally {
    await bad.close();
  }
  const failIds = findings.filter((f) => !f.pass).map((f) => f.id);
  const families = ['api.unauth-data', 'api.cors', 'api.unauth-write', 'api.rate-limit', 'xss.reflected'];
  for (const fam of families) {
    const hit = failIds.find((id) => id.startsWith(fam));
    assert.ok(hit, `expected a ${fam}* failure on known-bad, got:\n  ${failIds.join('\n  ')}`);
    assert.ok(catalogEntryFor(hit!), `emitted ${hit} but it is not catalogued`);
  }
});

test('catalog: ids are unique', () => {
  const seen = new Set<string>();
  for (const c of CATALOG) {
    assert.ok(!seen.has(c.id), `duplicate catalog id ${c.id}`);
    seen.add(c.id);
  }
});

test('catalog: every SECRET_RULE resolves to the secret.* family', () => {
  for (const r of SECRET_RULES) {
    const entry = catalogEntryFor(`secret.${r.id}`);
    assert.ok(entry && entry.category === 'secrets', `secret rule ${r.id} has no catalog family`);
  }
});

test('numbering: every catalog id has a stable VTA number, unique, registry not stale', () => {
  // Completeness: every catalog id is numbered (else `npm run catalog` was not run).
  const missing = CATALOG.filter((c) => vtaNumber(c.id) === undefined).map((c) => c.id);
  assert.equal(missing.length, 0, `catalog ids without a VTA number (run \`npm run catalog\`):\n  ${missing.join('\n  ')}`);

  // Uniqueness: no two ids share a number.
  const byNum = new Map<number, string>();
  for (const [id, n] of Object.entries(CATALOG_NUMBERS)) {
    assert.ok(!byNum.has(n), `VTA number ${n} used by both ${byNum.get(n)} and ${id}`);
    byNum.set(n, id);
  }

  // Append-only / not-stale: re-running the assigner over the current catalog adds nothing.
  const reassigned = assignNumbers(CATALOG.map((c) => c.id), CATALOG_NUMBERS);
  assert.equal(Object.keys(reassigned).length, Object.keys(CATALOG_NUMBERS).length,
    'registry is stale — new catalog ids need numbers; run `npm run catalog`');
});

test('numbering: a concrete dynamic finding inherits its family number', () => {
  // header.x-frame-options has no own number; it inherits the `header.` family's.
  assert.equal(vtaNumber('header.x-frame-options'), vtaNumber('header.'));
  assert.match(vtaCode('header.x-frame-options'), /^VTA-\d{4}$/);
  assert.equal(vtaCode('this.id.does.not.exist'), 'VTA-????');
});

test('catalog: docs/CHECKS.md is up to date (run `npm run catalog`)', () => {
  const onDisk = readFileSync(CHECKS_MD, 'utf8');
  assert.equal(
    onDisk,
    renderCatalogMarkdown(),
    'docs/CHECKS.md is stale — regenerate it with `npm run catalog` and commit the result.',
  );
});
