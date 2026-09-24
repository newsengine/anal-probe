/**
 * Run-record + Priority-Status ledger. Proves each run is captured as a DB-ready record with one
 * sub-test per check (keyed by VTA number), that priority is derived correctly, and that the JSONL
 * ledger round-trips with monotonic run numbers.
 *
 * Imports dist/ so we test the shipped build.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildRunRecord, priorityOf, appendRun, readRuns, renderPriorityReport } from '../dist/ledger.js';
import type { Finding } from '../dist/types.js';

const F = (id: string, category: string, severity: string, pass: boolean, detail = 'x'): Finding =>
  ({ id, category, severity, pass, detail, title: id } as Finding);

test('ledger: buildRunRecord maps each finding to a numbered sub-test', () => {
  const findings = [
    F('tls.scheme', 'security', 'high', true),
    F('header.x-frame-options', 'security', 'medium', false),
    F('secret.aws.akid', 'secrets', 'high', false),
  ];
  const rec = buildRunRecord(findings, { target: 'https://x.test', actor: 'mike' });
  assert.equal(rec.subTests.length, 3);
  assert.equal(rec.actor, 'mike');
  const hdr = rec.subTests.find((s) => s.id === 'header.x-frame-options')!;
  assert.match(hdr.code, /^VTA-\d{4}$/);
  assert.ok(typeof hdr.number === 'number', 'sub-test carries a VTA number');
  assert.equal(rec.summary.failed, 2);
});

test('ledger: priority escalates to CRITICAL on a leaked secret', () => {
  assert.equal(priorityOf(buildRunRecord([F('secret.aws.akid', 'secrets', 'high', false)], { target: 't' }).subTests), 'critical');
  assert.equal(priorityOf(buildRunRecord([F('exposed/.env', 'exposure', 'high', false)], { target: 't' }).subTests), 'critical');
  assert.equal(priorityOf(buildRunRecord([F('header.x-frame-options', 'security', 'high', false)], { target: 't' }).subTests), 'high');
  assert.equal(priorityOf(buildRunRecord([F('seo.title', 'seo', 'medium', false)], { target: 't' }).subTests), 'medium');
  assert.equal(priorityOf(buildRunRecord([F('tls.scheme', 'security', 'high', true)], { target: 't' }).subTests), 'clean');
});

test('ledger: JSONL round-trips with monotonic per-target run numbers', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vta-ledger-'));
  const file = join(dir, 'runs.jsonl');
  try {
    const r1 = appendRun(file, buildRunRecord([F('tls.scheme', 'security', 'high', true)], { target: 'https://a.test' }));
    const r2 = appendRun(file, buildRunRecord([F('tls.scheme', 'security', 'high', false)], { target: 'https://a.test' }));
    const rB = appendRun(file, buildRunRecord([F('tls.scheme', 'security', 'high', true)], { target: 'https://b.test' }));
    assert.equal(r1.runNumber, 1);
    assert.equal(r2.runNumber, 2, 'same target increments');
    assert.equal(rB.runNumber, 1, 'different target starts its own sequence');
    const all = readRuns(file);
    assert.equal(all.length, 3);
    assert.equal(all[1].summary.failed, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ledger: priority report leads with the status banner + shows trend', () => {
  const prev = buildRunRecord([F('a', 'security', 'high', false), F('b', 'security', 'high', false)], { target: 't', runNumber: 1 } as any);
  const cur = buildRunRecord([F('secret.aws.akid', 'secrets', 'high', false)], { target: 't', runNumber: 2 } as any);
  const out = renderPriorityReport(cur, prev);
  assert.match(out, /PRIORITY STATUS: .*CRITICAL/);
  assert.match(out, /VTA-\d{4}/);
  assert.match(out, /trend:/);
});
