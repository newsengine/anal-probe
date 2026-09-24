/**
 * #35 — fix pack. Proves deterministic header fixes are emitted for missing-header findings, snippets
 * cover the common platforms, and the pack is keyed by VTA number and grouped by severity.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderFixPack, missingHeaderLines } from '../dist/fixes.js';
import type { Finding } from '../dist/types.js';

const F = (id: string, category: string, severity: string, pass: boolean, fix?: string): Finding =>
  ({ id, category, severity, pass, detail: 'd', title: id, fix } as Finding);

test('fixes: missingHeaderLines only for failing header findings', () => {
  const lines = missingHeaderLines([
    F('header.strict-transport-security', 'security', 'high', false),
    F('header.x-frame-options', 'security', 'medium', true), // passes → excluded
    F('header.content-security-policy', 'security', 'high', false),
  ]);
  assert.ok(lines.some((l) => l.startsWith('Strict-Transport-Security:')));
  assert.ok(lines.some((l) => l.startsWith('Content-Security-Policy:')));
  assert.ok(!lines.some((l) => l.startsWith('X-Frame-Options:')));
});

test('fixes: fix pack has header snippets + VTA-keyed checklist grouped by severity', () => {
  const md = renderFixPack([
    F('header.strict-transport-security', 'security', 'high', false, 'Send HSTS'),
    F('seo.title', 'seo', 'medium', false, 'Add a title'),
    F('tls.scheme', 'security', 'high', true), // pass → not listed
  ], { target: 'https://x.test' });
  assert.match(md, /# Fix pack/);
  assert.match(md, /### Add these security headers/);
  assert.match(md, /Next\.js/);
  assert.match(md, /add_header Strict-Transport-Security/);
  assert.match(md, /## HIGH \(1\)/);
  assert.match(md, /## MEDIUM \(1\)/);
  assert.match(md, /VTA-\d{4}/);
  assert.ok(!md.includes('tls.scheme'), 'passing checks are not in the pack');
});

test('fixes: clean scan yields a clean pack', () => {
  const md = renderFixPack([F('tls.scheme', 'security', 'high', true)], { target: 'https://x.test' });
  assert.match(md, /No issues to fix/);
});
