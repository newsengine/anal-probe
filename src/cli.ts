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
import { probe, summarize, normalizeUrl, discoverPages, ALL_CATEGORIES, type Category, type Finding, type Severity, type ScanOptions } from './probe.js';
import { runNpmAudit, failsAtLevel } from './audit.js';
import { toSarif } from './sarif.js';
import { buildBaseline, applyBaseline, type Baseline } from './baseline.js';
import { loadConfig } from './config.js';
import { recon, parsePorts } from './active.js';
import { identifyEdge } from './host.js';

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
  host: '🖥️  Host & infrastructure',
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

const failGate = (findings: Finding[], failOn: 'high' | 'medium' | 'any'): boolean => {
  const gate = findings.filter((f) => !f.pass);
  const h = gate.filter((f) => f.severity === 'high').length;
  const m = gate.filter((f) => f.severity === 'medium').length;
  return failOn === 'any' ? gate.length > 0 : failOn === 'medium' ? h + m > 0 : h > 0;
};

/** Scan a list of URLs (from --urls or --crawl) and aggregate — combined non-zero exit if any fails. */
async function runBatch(targets: string[], opts: ScanOptions, o: { failOn: 'high' | 'medium' | 'any'; quiet: boolean; json: boolean }) {
  const rows = [];
  let anyFail = false;
  for (const url of targets) {
    const findings = await probe(url, opts);
    const failed = failGate(findings, o.failOn);
    if (failed) anyFail = true;
    rows.push({ url, summary: summarize(findings), failed, findings });
  }
  if (o.json) {
    console.log(JSON.stringify(rows.map((r) => ({ url: r.url, summary: r.summary, failed: r.failed })), null, 2));
  } else {
    console.log(`\n🔬 anal-probe — scanned ${targets.length} URL(s)\n`);
    for (const r of rows) {
      const s = r.summary;
      console.log(`${r.failed ? '🟥' : '✅'} ${r.url} — ${s.passed} passed, ${s.failed} failed  (🟥 ${s.failHigh} · 🟧 ${s.failMedium} · 🟨 ${s.failLow})`);
      if (!o.quiet) for (const f of r.findings.filter((x) => !x.pass)) console.log(`     ${SEV_ICON[f.severity]} [${f.category}] ${f.title}`);
    }
    console.log('');
  }
  process.exit(anyFail ? 1 : 0);
}

// ACTIVE recon subcommand — opt-in, authorization-gated, CDN-guarded. Identify only (no exploitation).
async function runRecon() {
  const target = process.argv[3];
  if (!target || target.startsWith('-')) {
    console.error('usage: anal-probe recon <host|url> --yes-i-am-authorized [--ports common|all|top1000|22,80,...] [--force] [--timeout <ms>] [--json]');
    process.exit(2); return;
  }
  if (!flag('--yes-i-am-authorized')) {
    console.error('⚠️  Active reconnaissance (port scanning) sends real connections to the target.\n' +
      '    Only run against systems you OWN or are explicitly AUTHORIZED to test — unauthorized scanning may be illegal.\n' +
      '    This is IDENTIFY-ONLY: no exploitation, no DoS/flooding, no credential brute-forcing.\n' +
      '    Re-run with --yes-i-am-authorized to confirm authorization.');
    process.exit(2); return;
  }
  let host: string;
  try { host = new URL(normalizeUrl(target)).hostname; } catch { console.error(`invalid target: ${target}`); process.exit(2); return; }

  // CDN guard: the resolved IPs of a CDN-fronted host are the edge, not the origin — scanning them scans
  // the CDN (a third party). Refuse unless --force.
  const probeRes = await fetch(normalizeUrl(target), { redirect: 'manual' }).catch(() => null);
  const edge = probeRes ? identifyEdge(probeRes.headers) : { providers: [], behindCdn: false };
  if (edge.behindCdn && !flag('--force')) {
    console.error(`🛑 ${host} is served via ${edge.providers.join('/')} (a CDN/edge). Its resolved IPs are ${edge.providers.join('/')} nodes,\n` +
      `    not your origin — scanning them scans ${edge.providers.join('/')}'s infrastructure (and likely breaks their ToS).\n` +
      `    Scan your origin's real IP directly instead. Override with --force ONLY if you're authorized to scan these IPs.`);
    process.exit(2); return;
  }

  const ports = parsePorts(arg('--ports'));
  const tRaw = arg('--timeout');
  const timeoutMs = tRaw && Number(tRaw) > 0 ? Number(tRaw) : undefined;
  console.error(`scanning ${host} — ${ports.length} port(s)${edge.behindCdn ? ' (forced, note: CDN edge)' : ''}…`);
  const result = await recon(host, ports, { timeoutMs });

  if (flag('--json')) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`\n🖥️  recon ${host}  (${result.ips.join(', ') || 'no A record'}) — ${result.open.length} open of ${result.scanned} scanned\n`);
    for (const p of result.open) {
      const s = p.service;
      const icon = s ? SEV_ICON[s.severity] : 'ℹ️ ';
      console.log(`  ${icon} ${p.port}/tcp  ${s ? s.name : 'open'}${s?.note ? ` — ${s.note}` : ''}`);
      if (p.banner) console.log(`        banner: ${p.banner}`);
    }
    if (!result.open.length) console.log('  (no open ports found)');
    console.log('');
  }
  process.exit(result.open.some((p) => p.service?.severity === 'high') ? 1 : 0);
}

async function main() {
  if (process.argv[2] === 'audit') return runAudit();
  if (process.argv[2] === 'recon') return runRecon();

  const cfgResult = loadConfig(arg('--config'));
  if (cfgResult.error) { console.error(cfgResult.error); process.exit(2); }
  const config = cfgResult.config;

  const rawUrl = process.argv[2];
  if (!rawUrl || rawUrl.startsWith('-')) {
    console.error('usage:\n  npx github:newsengine/anal-probe <url> [--only ...] [--skip ...] [--cors-path <p>] [--rate-limit-path <p>] [--timeout <ms>] [--cookie "<raw cookie>"] [--header "K: V"] [--crawl <N>] [--urls <file>] [--config <file>] [--fail-on high|medium|any] [--json] [--quiet]\n  npx github:newsengine/anal-probe audit [--prod] [--level low|moderate|high|critical] [--json]');
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

  // Options: CLI flags win, else fall back to .analproberc.json.
  const opts: ScanOptions = {
    only: list(arg('--only')) ?? (config.only as Category[] | undefined),
    skip: list(arg('--skip')) ?? (config.skip as Category[] | undefined),
    corsTestPath: arg('--cors-path') ?? config.corsPath,
    rateLimitPath: arg('--rate-limit-path') ?? config.rateLimitPath,
    allowReportOnlyCsp: flag('--allow-report-only-csp') || !!config.allowReportOnlyCsp,
    maxCrawl: arg('--max-crawl') ? num('--max-crawl', 25) : config.maxCrawl,
    timeoutMs: arg('--timeout') ? num('--timeout', 10_000) : config.timeoutMs,
    extraHeaders: hasAuth ? extraHeaders : undefined,
  };
  const failOn = (arg('--fail-on') ?? config.failOn ?? 'high') as 'high' | 'medium' | 'any';
  const quiet = flag('--quiet') || !!config.quiet;

  // Batch mode: --urls <file> (one URL per line) or --crawl <N> (homepage + N same-origin pages).
  const urlsFile = arg('--urls');
  const crawlN = arg('--crawl') ? num('--crawl', 0) : config.crawl;
  if (urlsFile) {
    let targets: string[] = [];
    try { targets = readFileSync(urlsFile, 'utf8').split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#')).map(normalizeUrl); }
    catch (e) { console.error(`could not read --urls ${urlsFile}: ${String((e as any)?.message || e)}`); process.exit(2); }
    if (!targets.length) { console.error(`--urls ${urlsFile} contains no URLs`); process.exit(2); }
    return runBatch(targets, opts, { failOn, quiet, json: flag('--json') }); // batch even for a single listed URL
  }
  if (crawlN) {
    const targets = [url, ...await discoverPages(url, crawlN, opts)];
    if (targets.length > 1) return runBatch(targets, opts, { failOn, quiet, json: flag('--json') });
    // only the homepage was found — fall through to the normal single-URL flow below
  }

  const findings = await probe(url, opts);
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

  const gHigh = gateFails.filter((f) => f.severity === 'high').length;
  const gMed = gateFails.filter((f) => f.severity === 'medium').length;
  const shouldFail =
    failOn === 'any' ? gateFails.length > 0 :
    failOn === 'medium' ? gHigh + gMed > 0 :
    gHigh > 0;
  process.exit(shouldFail ? 1 : 0);
}

main().catch((e) => { console.error('probe error:', e); process.exit(2); });
