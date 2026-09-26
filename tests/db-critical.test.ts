/**
 * Unit / fixture tests for the Dynamic Business CMS critical-path suite.
 * No live network / secrets required — SKIP paths and pure helpers only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  dbCriticalCheckSpecs,
  htmlReflectsXss,
  profilesDumpDetected,
  totpCode,
  TINY_PNG,
  runDbCritical,
} from '../dist/db-critical.js';
import { catalogEntryFor, CATALOG } from '../dist/catalog.js';

test('db-critical: catalog specs are registered with stable ids', () => {
  const specs = dbCriticalCheckSpecs();
  assert.ok(specs.length >= 8, `expected ≥8 specs, got ${specs.length}`);
  for (const s of specs) {
    assert.match(s.id, /^db\./, `id ${s.id} must be under db.*`);
    const entry = catalogEntryFor(s.id);
    assert.ok(entry, `catalog missing ${s.id} — run npm run catalog`);
    assert.equal(entry!.category, 'dbcms');
  }
  const ids = CATALOG.filter((c) => c.category === 'dbcms').map((c) => c.id);
  assert.deepEqual(ids.sort(), specs.map((s) => s.id).sort());
});

test('db-critical: TINY_PNG is a valid PNG signature', () => {
  assert.equal(TINY_PNG[0], 0x89);
  assert.equal(TINY_PNG[1], 0x50); // P
  assert.equal(TINY_PNG[2], 0x4e); // N
  assert.equal(TINY_PNG[3], 0x47); // G
  assert.ok(TINY_PNG.length < 200);
});

test('db-critical: totpCode is 6 digits and stable within a 30s window', () => {
  const secret = 'JBSWY3DPEHPK3PXP'; // known test vector base32 ("Hello!")
  const t = 1_111_111_110_000; // fixed
  const a = totpCode(secret, t);
  const b = totpCode(secret, t + 1000);
  assert.match(a, /^\d{6}$/);
  assert.equal(a, b);
});

test('db-critical: htmlReflectsXss detects raw payloads', () => {
  const payload = `<img src=x onerror=alert(1)>`;
  assert.equal(htmlReflectsXss(`<html>${payload}</html>`, payload), true);
  assert.equal(htmlReflectsXss('<html>&lt;img src=x onerror=alert(1)&gt;</html>', payload), false);
  assert.equal(htmlReflectsXss('<html>Invalid token</html>', payload), false);
});

test('db-critical: profilesDumpDetected thresholds', () => {
  assert.equal(profilesDumpDetected(401, []), false);
  assert.equal(profilesDumpDetected(403, [{}, {}, {}, {}, {}, {}]), false);
  assert.equal(profilesDumpDetected(200, [{}, {}]), false);
  assert.equal(profilesDumpDetected(200, new Array(6).fill({})), true);
  assert.equal(profilesDumpDetected(200, 'nope'), false);
});

test('db-critical: missing creds produce SKIP passes (no false-fail)', async () => {
  // Ensure role envs are unset for this process.
  const keys = [
    'VTA_EDITOR_EMAIL', 'VTA_EDITOR_PASSWORD',
    'VTA_SUPERADMIN_EMAIL', 'VTA_SUPERADMIN_PASSWORD',
    'VTA_USER_EMAIL', 'VTA_USER_PASSWORD',
    'VTA_UNPUBLISHED_ARTICLE_URL', 'VTA_STRIPE_AMOUNT_PROBE',
  ];
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) { saved[k] = process.env[k]; delete process.env[k]; }

  try {
    const findings = await runDbCritical('https://example.com', { timeoutMs: 5000 });
    assert.ok(findings.length >= 8);
    for (const f of findings) {
      if (f.id.startsWith('db.auth.') || f.id === 'db.api.uploads-ad' || f.id === 'db.api.uploads-empty'
        || f.id === 'db.api.profiles-rls' || f.id === 'db.editorial.golden-path' || f.id === 'db.api.stripe-amount') {
        assert.equal(f.pass, true, `${f.id} must SKIP-pass without creds, got fail: ${f.detail}`);
        assert.match(f.detail, /^SKIP:/i, `${f.id} detail should start with SKIP:`);
      }
    }
    // Probe checks (ad-track / unsubscribe) may pass or fail against example.com — either is fine;
    // they must not crash the suite.
    assert.ok(findings.every((f) => typeof f.id === 'string'));
  } finally {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
});
