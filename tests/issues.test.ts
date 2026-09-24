/**
 * #34 — GitHub-issue feed planner. Proves the plan is idempotent: failing checks open/update one issue
 * each (keyed by VTA number + target + id), passing checks close their issue, and passes/info never file.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { planIssueActions, issueKey, markerFor, keyFromBody } from '../dist/issues.js';
import type { Finding } from '../dist/types.js';

const F = (id: string, category: string, severity: string, pass: boolean): Finding =>
  ({ id, category, severity, pass, detail: 'd', title: id, fix: 'do the thing' } as Finding);
const TARGET = 'https://shop.example';

test('issues: marker key round-trips', () => {
  const key = issueKey(TARGET, F('header.x-frame-options', 'security', 'medium', false));
  assert.equal(keyFromBody(`intro\n${markerFor(key)}\nrest`), key);
  assert.match(key, /^VTA-\d{4}:shop\.example:header\.x-frame-options$/);
});

test('issues: failing checks open, passing/info do not file', () => {
  const findings = [
    F('secret.aws.akid', 'secrets', 'high', false),
    F('tls.scheme', 'security', 'high', true),          // pass → no issue
    F('exposure.none', 'exposure', 'info', true),        // info pass → no issue
    F('header.x-frame-options', 'security', 'medium', false),
  ];
  const plan = planIssueActions(findings, { target: TARGET, existing: [] });
  assert.equal(plan.toOpen.length, 2);
  assert.equal(plan.toUpdate.length, 0);
  assert.equal(plan.toClose.length, 0);
  assert.ok(plan.toOpen[0].labels.includes('vta'));
});

test('issues: existing issue for a still-failing check updates, not duplicates', () => {
  const f = F('secret.aws.akid', 'secrets', 'high', false);
  const key = issueKey(TARGET, f);
  const plan = planIssueActions([f], { target: TARGET, existing: [{ number: 7, state: 'open', key }] });
  assert.equal(plan.toOpen.length, 0);
  assert.equal(plan.toUpdate.length, 1);
  assert.equal(plan.toUpdate[0].number, 7);
});

test('issues: a check that now passes closes its open issue', () => {
  const failing = F('secret.aws.akid', 'secrets', 'high', false);
  const key = issueKey(TARGET, failing);
  // This scan: the check passes now (so it is NOT in failing set) but an open issue exists.
  const plan = planIssueActions([F('secret.aws.akid', 'secrets', 'high', true)], { target: TARGET, existing: [{ number: 9, state: 'open', key }] });
  assert.equal(plan.toClose.length, 1);
  assert.equal(plan.toClose[0].number, 9);
});

test('issues: another host issues are never touched (multi-target repo safety)', () => {
  const f = F('secret.aws.akid', 'secrets', 'high', false);
  const otherKey = issueKey('https://other.example', f);
  const plan = planIssueActions([f], { target: TARGET, existing: [{ number: 3, state: 'open', key: otherKey }] });
  // our finding opens its own issue; the other-host issue is left completely alone.
  assert.equal(plan.toOpen.length, 1);
  assert.equal(plan.toClose.length, 0);
});
