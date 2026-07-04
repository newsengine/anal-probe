// tests/vuln-feed.test.ts — covers the auto-updating client-side-component vulnerability feed.
// Imports the compiled generated data module + the components module (which re-exports VULN_DB as an alias).
import test from 'node:test';
import assert from 'node:assert/strict';
import { VULN_DATA, VULN_DATA_META } from '../dist/vuln-data.js';
import { VULN_DB, matchVulnerabilities, detectComponents } from '../dist/components.js';
// Pure helpers factored out of the updater (plain ESM, no build step needed).
import { normalizeSeverity, mapRetireVulns, mergeTables } from '../scripts/update-vuln-db.mjs';

const VALID_SEVERITIES = new Set(['high', 'medium', 'low']);

test('vuln-feed: VULN_DATA is non-empty and every entry is well-formed', () => {
  const libs = Object.keys(VULN_DATA);
  assert.ok(libs.length > 0, 'VULN_DATA has at least one library');
  let total = 0;
  for (const lib of libs) {
    assert.ok(Array.isArray(VULN_DATA[lib]) && VULN_DATA[lib].length > 0, `${lib} has entries`);
    for (const e of VULN_DATA[lib]) {
      total++;
      assert.equal(typeof e.below, 'string', `${lib}.below is a string`);
      assert.ok(e.below.length > 0, `${lib}.below non-empty`);
      assert.ok(VALID_SEVERITIES.has(e.severity), `${lib} severity "${e.severity}" is valid`);
      assert.equal(typeof e.ref, 'string', `${lib}.ref is a string`);
      assert.ok(e.ref.length > 0, `${lib}.ref non-empty`);
      assert.equal(typeof e.note, 'string', `${lib}.note is a string`);
      assert.ok(e.note.length > 0, `${lib}.note non-empty`);
    }
  }
  assert.ok(total > 0, 'at least one range overall');
});

test('vuln-feed: VULN_DATA_META describes the generated table', () => {
  assert.equal(typeof VULN_DATA_META.generatedAt, 'string');
  assert.ok(!Number.isNaN(Date.parse(VULN_DATA_META.generatedAt)), 'generatedAt is an ISO date');
  assert.equal(typeof VULN_DATA_META.source, 'string');
  assert.equal(typeof VULN_DATA_META.count, 'number');
});

test('vuln-feed: VULN_DB alias is the same table as VULN_DATA', () => {
  assert.equal(VULN_DB, VULN_DATA, 'VULN_DB is an alias reference to VULN_DATA');
});

test('vuln-feed: curated seed is preserved (spot-checks not dropped by the feed)', () => {
  // lodash high-sev RCE range must survive.
  assert.ok((VULN_DATA.lodash || []).some((e) => e.below === '4.17.21' && e.severity === 'high'),
    'lodash 4.17.21 high-sev range present');
  // jquery XSS range must survive.
  assert.ok((VULN_DATA.jquery || []).some((e) => e.below === '3.5.0'), 'jquery 3.5.0 range present');
});

test('vuln-feed: a known range still matches via matchVulnerabilities (lodash 4.17.11 → high)', () => {
  const html = `<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.11/lodash.min.js"></script>`;
  const c = detectComponents(html, 'https://x.com/').find((d) => d.name === 'lodash');
  assert.ok(c && c.version === '4.17.11', 'detected lodash 4.17.11');
  const v = matchVulnerabilities(c);
  assert.ok(v, 'lodash 4.17.11 matched a vuln');
  assert.equal(v.severity, 'high');
});

// ---- pure unit tests for the updater's mapping helpers ----

test('vuln-feed: normalizeSeverity maps to high|medium|low', () => {
  assert.equal(normalizeSeverity('critical'), 'high');
  assert.equal(normalizeSeverity('HIGH'), 'high');
  assert.equal(normalizeSeverity('moderate'), 'medium');
  assert.equal(normalizeSeverity('low'), 'low');
  assert.equal(normalizeSeverity('none'), 'low');
  assert.equal(normalizeSeverity('weird-unknown'), 'medium');
});

test('vuln-feed: mapRetireVulns extracts {below,severity,ref,note} and skips entries without below', () => {
  const mapped = mapRetireVulns([
    { below: '4.17.21', severity: 'high', identifiers: { CVE: ['CVE-2021-23337'], summary: 'command injection' } },
    { atOrAbove: '1.0.0', severity: 'low', identifiers: { summary: 'no upper bound' } }, // no `below` → skipped
  ]);
  assert.equal(mapped.length, 1);
  assert.equal(mapped[0].below, '4.17.21');
  assert.equal(mapped[0].severity, 'high');
  assert.equal(mapped[0].ref, 'CVE-2021-23337');
  assert.match(mapped[0].note, /command injection/);
});

test('vuln-feed: mergeTables unions by library and dedupes by below+ref', () => {
  const seed = { lodash: [{ below: '4.17.21', severity: 'high', ref: 'CVE-A', note: 'seed' }] };
  const feed = {
    lodash: [
      { below: '4.17.21', severity: 'high', ref: 'CVE-A', note: 'dup, dropped' }, // dedup
      { below: '4.17.12', severity: 'medium', ref: 'CVE-B', note: 'new' },
    ],
    jquery: [{ below: '3.5.0', severity: 'medium', ref: 'CVE-C', note: 'feed-only lib' }],
  };
  const merged = mergeTables(seed, feed);
  assert.equal(merged.lodash.length, 2, 'dedup kept 2 lodash entries');
  assert.equal(merged.lodash[0].note, 'seed', 'seed entry preserved first');
  assert.ok(merged.jquery, 'feed-only library added');
});
