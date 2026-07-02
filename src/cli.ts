#!/usr/bin/env node
// src/cli.ts
// `npx github:newsengine/anal-probe <url> [options]`
// Point it at any deployed app and it reports everything wrong: leaked secrets, exposed files, broken
// links, missing security headers, SEO/a11y/performance gaps. Exits non-zero so it can gate CI.
//
//   --only security,secrets         only run these categories
//   --skip seo,a11y                 run everything except these
//   --cors-path /api/health         test CORS reflection on this path
//   --rate-limit-path /api/health   burst-test this path for rate limiting (expects 429)
//   --allow-report-only-csp         accept CSP Report-Only as a pass
//   --max-crawl 25                  how many links/scripts to fetch-check
//   --fail-on high|medium|any       CI exit threshold (default high)
//   --json                          machine-readable output
//   --sarif                         emit SARIF 2.1.0 (for GitHub code scanning / upload-sarif)
//   --baseline <file>               only fail on findings NOT in this baseline file
//   --write-baseline <file>         write current failing findings as a baseline, then exit 0
//
// Subcommand:
//   anal-probe audit [--prod] [--level low|moderate|high|critical] [--json]   # npm audit gate

import { readFileSync, writeFileSync } from 'node:fs';
import { probe, summarize, normalizeUrl, ALL_CATEGORIES, type Category, type Finding, type Severity } from './probe.js';
import { runNpmAudit, failsAtLevel } from './audit.js';
import { toSarif } from './sarif.js';
import { buildBaseline, applyBaseline, type Baseline } from './baseline.js';

const VERSION = (() => {
  try { return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version as string; }
  catch { return '0.0.0'; }
})();

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const flag = (name: string) => process.argv.includes(name);
const list = (v?: string) => (v ? (v.split(',').map((s) => s.trim()).filter(Boolean) as Category[]) : undefined);

const SEV_ICON: Record<Severity, string> = { high: '🟥', medium: '🟧', low: '🟨', info: 'ℹ️ ' };
const CAT_TITLE: Record<Category, string> = {
  security: '🔐 Security', secrets: '🔑 Leaked secrets', exposure: '📂 Exposed files & debug',
  dns: '🌐 DNS & email', reliability: '🔗 Reliability', seo: '🔎 SEO', a11y: '♿ Accessibility', performance: '⚡ Performance',
  agent: '🤖 Agent readiness',
  framework: '🧩 Framework-specific',
};

async function runAudit() {
  const level = arg('--level') || 'high';
  const result = await runNpmAudit(process.cwd(), flag('--prod'));
  if (flag('--json')) { console.log(JSON.stringify(result, null, 2)); }
  else if (result.error) { console.error('audit error:', result.error); }
  else {
    console.log(`\n🔐 anal-probe audit (npm audit)\n`);
    for (const sev of ['critical', 'high', 'moderate', 'low', 'info']) console.log(`  ${sev}: ${result.counts[sev] ?? 0}`);
    console.log(`\n${result.total} total advisories\n`);
  }
  process.exit(result.error ? 2 : failsAtLevel(result, level) ? 1 : 0);
}

async function main() {
  if (process.argv[2] === 'audit') return runAudit();

  const rawUrl = process.argv[2];
  if (!rawUrl || rawUrl.startsWith('-')) {
    console.error('usage:\n  npx github:newsengine/anal-probe <url> [--only ...] [--skip ...] [--cors-path <p>] [--rate-limit-path <p>] [--timeout <ms>] [--cookie "<raw cookie>"] [--header "K: V"] [--fail-on high|medium|any] [--json] [--quiet]\n  npx github:newsengine/anal-probe audit [--prod] [--level low|moderate|high|critical] [--json]');
    process.exit(2);
  }
  const url = normalizeUrl(rawUrl); // accept bare domains (example.com -> https://example.com)
  try { new URL(url); } catch { console.error(`invalid URL: ${rawUrl}`); process.exit(2); }

  // Parse numeric flags defensively so a typo can't silently become NaN and disable the cap/timeout.
  const num = (name: string, dflt: number): number => {
    const raw = arg(name);
    if (raw === undefined) return dflt;
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) { console.error(`${name} must be a positive number (got "${raw}")`); process.exit(2); }
    return n;
  };

  // Auth for scanning behind login: --cookie "<raw cookie header>" and/or repeatable --header "K: V".
  // These are sent ONLY on same-origin requests (see ScanOptions.extraHeaders).
  const extraHeaders: Record<string, string> = {};
  const cookie = arg('--cookie');
  if (cookie) extraHeaders['cookie'] = cookie;
  for (let i = 0; i < process.argv.length; i++) {
    if (process.argv[i] === '--header') {
      const raw = process.argv[i + 1] || '';
      const idx = raw.indexOf(':');
      if (idx > 0) extraHeaders[raw.slice(0, idx).trim().toLowerCase()] = raw.slice(idx + 1).trim();
      else { console.error(`--header must be "Name: value" (got "${raw}")`); process.exit(2); }
    }
  }
  const hasAuth = Object.keys(extraHeaders).length > 0;

  const findings = await probe(url, {
    only: list(arg('--only')),
    skip: list(arg('--skip')),
    corsTestPath: arg('--cors-path'),
    rateLimitPath: arg('--rate-limit-path'),
    allowReportOnlyCsp: flag('--allow-report-only-csp'),
    maxCrawl: arg('--max-crawl') ? num('--max-crawl', 25) : undefined,
    timeoutMs: arg('--timeout') ? num('--timeout', 10_000) : undefined,
    extraHeaders: hasAuth ? extraHeaders : undefined,
  });
  const sum = summarize(findings);

  // --write-baseline: snapshot today's failing findings and exit 0 (nothing to gate on the first run).
  const writeBaselinePath = arg('--write-baseline');
  if (writeBaselinePath) {
    const baseline = buildBaseline(findings, url);
    writeFileSync(writeBaselinePath, JSON.stringify(baseline, null, 2) + '\n');
    console.error(`wrote baseline (${baseline.keys.length} finding(s)) to ${writeBaselinePath}`);
    process.exit(0);
  }

  // --baseline: partition failing findings into new (gate on these) vs already-accepted.
  const baselinePath = arg('--baseline');
  let diff: { newFailures: Finding[]; baselined: Finding[] } | null = null;
  if (baselinePath) {
    let baseline: Baseline = { keys: [] };
    try { baseline = JSON.parse(readFileSync(baselinePath, 'utf8')); }
    catch (e) { console.error(`could not read baseline ${baselinePath}: ${String((e as any)?.message || e)}`); process.exit(2); }
    diff = applyBaseline(findings, baseline);
  }

  // The set CI actually gates on: new-only when a baseline is in play, otherwise every failure.
  const gateFails = diff ? diff.newFailures : findings.filter((f) => !f.pass);

  if (flag('--sarif')) {
    // Report new-only under a baseline so the Security tab shows regressions, not accepted debt.
    console.log(JSON.stringify(toSarif(diff ? diff.newFailures : findings, { url, version: VERSION }), null, 2));
  } else if (flag('--json')) {
    console.log(JSON.stringify({ url, summary: sum, findings, ...(diff ? { baseline: { new: diff.newFailures.length, accepted: diff.baselined.length } } : {}) }, null, 2));
  } else {
    // --quiet: show only failures (good for CI logs); default shows passes too so a clean scan is visible.
    const quiet = flag('--quiet');
    console.log(`\n🔬 anal-probe — full app scan of ${url}${hasAuth ? ' (authenticated)' : ''}\n`);
    for (const cat of ALL_CATEGORIES) {
      const group = findings.filter((f) => f.category === cat);
      if (!group.length) continue;
      const failed = group.filter((g) => !g.pass).length;
      if (quiet && !failed) continue;
      console.log(`${CAT_TITLE[cat]}  ${failed ? `— ${failed} issue(s)` : '— ok'}`);
      for (const f of group as Finding[]) {
        if (quiet && f.pass) continue;
        const mark = f.pass ? '  ✅' : `  ${SEV_ICON[f.severity]}`;
        console.log(`${mark} [${f.severity.toUpperCase()}] ${f.title}`);
        console.log(`        ${f.detail}`);
        if (!f.pass && f.fix) console.log(`        ↳ fix: ${f.fix}`);
      }
      console.log('');
    }
    console.log(`${sum.passed} passed, ${sum.failed} failed  (🟥 ${sum.failHigh} high · 🟧 ${sum.failMedium} medium · 🟨 ${sum.failLow} low)`);
    if (diff) console.log(`baseline: ${diff.newFailures.length} new · ${diff.baselined.length} accepted`);
    console.log('');
  }

  const failOn = (arg('--fail-on') || 'high') as 'high' | 'medium' | 'any';
  const gHigh = gateFails.filter((f) => f.severity === 'high').length;
  const gMed = gateFails.filter((f) => f.severity === 'medium').length;
  const shouldFail =
    failOn === 'any' ? gateFails.length > 0 :
    failOn === 'medium' ? gHigh + gMed > 0 :
    gHigh > 0;
  process.exit(shouldFail ? 1 : 0);
}

main().catch((e) => { console.error('probe error:', e); process.exit(2); });
