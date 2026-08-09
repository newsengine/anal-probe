/**
 * Fixture coverage: prove marketed / core checks fire (true positive) and stay quiet (true negative).
 *
 * - known-bad  → MUST_FAIL_ON_BAD ids must appear with pass=false
 * - known-good → those leak/header fails must NOT appear as failures
 * - secret rules → each SECRET_RULES id hits a crafted sample; clean strings do not
 *
 * Imports dist/ so we test the shipped build (`npm test` builds first).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probe } from '../dist/probe.js';
import { scanSecrets, SECRET_RULES } from '../dist/core.js';
import { startKnownBad, startKnownGood } from './helpers/fixtures.ts';
import {
  MUST_FAIL_ON_BAD,
  MUST_NOT_FAIL_ON_GOOD,
  MUST_PASS_OR_ABSENT_FAIL_ON_GOOD,
  SECRET_RULE_IDS,
  SECRET_SAMPLES,
  SECRET_NEGATIVES,
} from './helpers/inventory.ts';
import type { Finding } from '../dist/types.js';

function byId(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.id === id);
}

function fails(findings: Finding[], id: string): boolean {
  return findings.some((f) => f.id === id && !f.pass);
}

function passes(findings: Finding[], id: string): boolean {
  return findings.some((f) => f.id === id && f.pass);
}

// ── known-bad: true positives ───────────────────────────────────────────────

test('fixture known-bad: required checks fail (true positives)', async () => {
  const srv = await startKnownBad();
  try {
    const findings = await probe(srv.url, {
      only: ['security', 'secrets', 'exposure', 'reliability', 'seo', 'a11y', 'components'],
      maxCrawl: 10,
      timeoutMs: 8000,
    });

    const missing: string[] = [];
    for (const id of MUST_FAIL_ON_BAD) {
      if (!fails(findings, id)) missing.push(id);
    }

    if (missing.length) {
      const dump = findings
        .filter((f) => !f.pass)
        .map((f) => `  FAIL ${f.id} — ${f.title}`)
        .join('\n');
      assert.fail(
        `known-bad missing true-positive failures for:\n  ${missing.join('\n  ')}\n\nActual failures:\n${dump || '  (none)'}`,
      );
    }
  } finally {
    await srv.close();
  }
});

test('fixture known-bad: secrets + exposure categories produce failures', async () => {
  const srv = await startKnownBad();
  try {
    const findings = await probe(srv.url, { only: ['secrets', 'exposure'], timeoutMs: 8000 });
    const secretFails = findings.filter((f) => f.category === 'secrets' && !f.pass);
    const exposureFails = findings.filter((f) => f.category === 'exposure' && !f.pass);
    assert.ok(secretFails.length >= 2, `expected ≥2 secret fails, got ${secretFails.length}`);
    assert.ok(exposureFails.length >= 5, `expected ≥5 exposure fails, got ${exposureFails.length}`);
  } finally {
    await srv.close();
  }
});

// ── known-good: true negatives ──────────────────────────────────────────────

test('fixture known-good: hardened headers pass', async () => {
  const srv = await startKnownGood();
  try {
    const findings = await probe(srv.url, {
      only: ['security', 'secrets', 'exposure'],
      timeoutMs: 8000,
    });

    for (const id of MUST_PASS_OR_ABSENT_FAIL_ON_GOOD) {
      if (id === 'secret.none') {
        assert.ok(passes(findings, 'secret.none') || !fails(findings, 'secret.stripe.sk_live'), 'no secret leaks');
        continue;
      }
      // tls.scheme always fails on http:// fixtures — skip as expected local limitation
      if (id === 'tls.scheme') continue;
      assert.ok(
        passes(findings, id) || !fails(findings, id),
        `expected ${id} to pass on known-good (got ${JSON.stringify(byId(findings, id))})`,
      );
    }
  } finally {
    await srv.close();
  }
});

test('fixture known-good: no leak/exposure true-positive IDs fail (true negatives)', async () => {
  const srv = await startKnownGood();
  try {
    const findings = await probe(srv.url, {
      only: ['security', 'secrets', 'exposure'],
      timeoutMs: 8000,
    });

    const bad: string[] = [];
    for (const id of MUST_NOT_FAIL_ON_GOOD) {
      if (fails(findings, id)) bad.push(id);
    }
    if (bad.length) {
      assert.fail(
        `known-good false positives (should not fail):\n  ${bad.join('\n  ')}\n` +
          findings
            .filter((f) => bad.includes(f.id))
            .map((f) => `  ${f.id}: ${f.detail}`)
            .join('\n'),
      );
    }
  } finally {
    await srv.close();
  }
});

test('fixture known-good: exposure emits clean pass when nothing exposed', async () => {
  const srv = await startKnownGood();
  try {
    const findings = await probe(srv.url, { only: ['exposure'], timeoutMs: 8000 });
    const failsOnly = findings.filter((f) => !f.pass);
    assert.equal(
      failsOnly.length,
      0,
      `exposure should be clean on known-good, failed:\n${failsOnly.map((f) => f.id).join(', ')}`,
    );
    assert.ok(passes(findings, 'exposure.none') || findings.every((f) => f.pass));
  } finally {
    await srv.close();
  }
});

// ── secret rule unit matrix ─────────────────────────────────────────────────

test('inventory: SECRET_RULE_IDS matches shipped SECRET_RULES', () => {
  const shipped = new Set(SECRET_RULES.map((r) => r.id));
  for (const id of SECRET_RULE_IDS) {
    assert.ok(shipped.has(id), `inventory lists ${id} but SECRET_RULES does not`);
  }
  for (const r of SECRET_RULES) {
    assert.ok(SECRET_RULE_IDS.includes(r.id), `SECRET_RULES has ${r.id} missing from inventory`);
  }
});

test('secret rules: each rule true-positive on crafted sample', () => {
  for (const id of SECRET_RULE_IDS) {
    const sample = SECRET_SAMPLES[id];
    assert.ok(sample, `missing SECRET_SAMPLES for ${id}`);
    const hits = scanSecrets(`prefix ${sample} suffix`);
    assert.ok(
      hits.some((h) => h.ruleId === id),
      `rule ${id} did not match its sample. hits=${hits.map((h) => h.ruleId).join(',')}`,
    );
  }
});

test('secret rules: public-looking strings do not false-positive live rules', () => {
  for (const blob of SECRET_NEGATIVES) {
    const hits = scanSecrets(blob);
    const liveHits = hits.filter((h) =>
      ['stripe.sk_live', 'stripe.rk_live', 'aws.akid', 'openai.key', 'anthropic.key'].includes(h.ruleId),
    );
    // pk_live and sk_test and anon JWT should not hit live secret rules
    assert.equal(
      liveHits.length,
      0,
      `false positive on ${JSON.stringify(blob)}: ${liveHits.map((h) => h.ruleId).join(',')}`,
    );
  }
});

// ── inventory hygiene ───────────────────────────────────────────────────────

test('inventory lists are non-empty and de-duplicated', () => {
  assert.ok(MUST_FAIL_ON_BAD.length >= 15, 'true-positive inventory too thin');
  assert.ok(MUST_NOT_FAIL_ON_GOOD.length >= 10, 'true-negative inventory too thin');
  assert.equal(new Set(MUST_FAIL_ON_BAD).size, MUST_FAIL_ON_BAD.length, 'duplicate in MUST_FAIL_ON_BAD');
  assert.equal(new Set(MUST_NOT_FAIL_ON_GOOD).size, MUST_NOT_FAIL_ON_GOOD.length);
});
