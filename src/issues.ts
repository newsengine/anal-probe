// src/issues.ts
// Turn scan findings into an idempotent set of GitHub-issue actions (#34). Each failing check maps to ONE
// tracking issue, keyed by (VTA number + target host + concrete finding id) so re-running the scan updates
// the existing issue instead of opening a duplicate, and auto-closes it once the check passes again.
//
// This module is PURE (no network): `planIssueActions()` computes what to open/update/close given the
// findings and the issues that already exist. The CLI does the actual gh/API writes (opt-in --apply), so
// the planner stays fully unit-testable and the safe default is dry-run.

import type { Finding, Severity } from './types.js';
import { vtaCode, catalogEntryFor } from './catalog.js';
import { refsFor } from './compliance.js';

/** A hidden marker embedded in every managed issue body so re-runs can match the same tracking issue. */
export function issueKey(target: string, finding: Finding): string {
  let host = target;
  try { host = new URL(target).host; } catch { /* keep as-is */ }
  return `${vtaCode(finding.id)}:${host}:${finding.id}`;
}
const MARK_OPEN = '<!-- vta-key:';
const MARK_CLOSE = '-->';
export function markerFor(key: string): string { return `${MARK_OPEN} ${key} ${MARK_CLOSE}`; }
export function keyFromBody(body: string): string | null {
  const m = body.match(/<!--\s*vta-key:\s*(\S+)\s*-->/);
  return m ? m[1] : null;
}

export interface ExistingIssue { number: number; state: 'open' | 'closed'; key: string }
export interface IssueSpec { key: string; title: string; body: string; labels: string[] }
export interface IssueActions {
  toOpen: IssueSpec[];              // failing checks with no existing open issue
  toUpdate: { number: number; spec: IssueSpec }[]; // failing checks that already have an issue (refresh body)
  toClose: { number: number; key: string }[];      // previously-open issues whose check now passes/absent
}

const SEV_LABEL: Record<Severity, string> = { high: 'severity:high', medium: 'severity:medium', low: 'severity:low', info: 'severity:info' };

function bodyFor(target: string, f: Finding, key: string): string {
  const spec = catalogEntryFor(f.id);
  const refs = refsFor(f.id);
  const std: string[] = [];
  if (refs.owasp) std.push(`OWASP ${refs.owasp}`);
  if (refs.apiTop10) std.push(refs.apiTop10);
  if (refs.cwe?.length) std.push(refs.cwe.join(' '));
  if (spec?.atlas?.length) std.push(`ATLAS ${spec.atlas.join(' ')}`);
  return [
    markerFor(key),
    `**Test:** \`${vtaCode(f.id)}\` — ${f.title}`,
    `**Target:** ${target}`,
    `**Severity:** ${f.severity}${std.length ? `  ·  **Standards:** ${std.join(', ')}` : ''}`,
    `**Category:** ${f.category}  ·  **Check id:** \`${f.id}\``,
    '',
    `**What we found:** ${f.detail}`,
    '',
    f.fix ? `**How to fix:** ${f.fix}` : '',
    '',
    '---',
    '_Opened automatically by VibeTesting Agent. It will auto-close when this check passes on a later scan._',
  ].filter((l) => l !== '').join('\n');
}

function titleFor(target: string, f: Finding): string {
  let host = target;
  try { host = new URL(target).host; } catch { /* keep */ }
  return `[${vtaCode(f.id)}] ${f.title} — ${host}`;
}

/**
 * Compute the idempotent open/update/close plan.
 * - a FAILING finding → open (new) or update (existing issue for its key)
 * - an existing OPEN issue whose key no longer maps to a failing finding → close (fixed / no longer seen)
 * Only failing findings produce issues (passes/info are not filed).
 */
export function planIssueActions(findings: Finding[], opts: { target: string; existing?: ExistingIssue[] }): IssueActions {
  let host = opts.target;
  try { host = new URL(opts.target).host; } catch { /* keep */ }
  // Only manage issues for THIS target host — a repo may track several sites; never close another's.
  const existing = (opts.existing ?? []).filter((e) => e.key.includes(`:${host}:`));
  const byKey = new Map<string, ExistingIssue>();
  for (const e of existing) byKey.set(e.key, e);

  const failing = findings.filter((f) => !f.pass && f.severity !== 'info');
  const failingKeys = new Set<string>();
  const toOpen: IssueSpec[] = [];
  const toUpdate: { number: number; spec: IssueSpec }[] = [];

  for (const f of failing) {
    const key = issueKey(opts.target, f);
    if (failingKeys.has(key)) continue; // dedupe within a single scan
    failingKeys.add(key);
    const spec: IssueSpec = { key, title: titleFor(opts.target, f), body: bodyFor(opts.target, f, key), labels: ['vta', `vta:${f.category}`, SEV_LABEL[f.severity]] };
    const prior = byKey.get(key);
    if (prior) toUpdate.push({ number: prior.number, spec });
    else toOpen.push(spec);
  }

  const toClose = existing
    .filter((e) => e.state === 'open' && !failingKeys.has(e.key))
    .map((e) => ({ number: e.number, key: e.key }));

  return { toOpen, toUpdate, toClose };
}

/** One-line human summary of a plan (for CLI dry-run output). */
export function summarizeActions(a: IssueActions): string {
  return `${a.toOpen.length} to open · ${a.toUpdate.length} to update · ${a.toClose.length} to close`;
}
