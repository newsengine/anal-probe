// src/inject.ts
// #43 — active injection engine (epic #41). Parameter-driven detection of the classic injection classes
// over the coverage map's real endpoint+param pairs. OPT-IN and AUTHORIZED only (opts.authorizedActive):
// it sends crafted values, so it never runs by default. NON-DESTRUCTIVE: GET query parameters only (no
// writes / no DoS / no brute-force); time-based probes use a single short sleep, capped. Every hit carries
// minimal evidence. White-hat: identify, never damage.
//
// Detectors are PURE (given a `Prober`), so they unit-test without a network; activeInjectionScan wires the
// real HTTP + timing on top.

import type { Finding, ScanContext, Severity } from './types.js';
import { safeFetch } from './core.js';
import { buildCoverageMap } from './crawl-map.js';

export interface Probe { status: number; body: string; ms: number }
export type Prober = (value: string) => Promise<Probe>;

export interface InjectionHit { kind: 'sqli' | 'ssti' | 'cmdi' | 'traversal'; severity: Severity; detail: string; evidence: string }

const f = (id: string, title: string, severity: Severity, pass: boolean, detail: string, fix?: string): Finding =>
  ({ category: 'security', id, title, severity, pass, detail, fix });

// ── signatures ────────────────────────────────────────────────────────────────────────────────────
const SQL_ERROR = /SQL syntax|mysql_fetch|you have an error in your sql|ORA-\d{5}|PostgreSQL.*ERROR|PG::\w+Error|SQLite3?::|SQLSTATE\[|Unclosed quotation mark|quoted string not properly terminated|near ".*": syntax error|SqlException|MySqlException/i;
const PASSWD = /root:.*?:0:0:/;
const TIME_MS = 3;                 // SLEEP(3) — real payload delay
const TIME_THRESHOLD_MS = 2200;    // flag if payload is >~2.2s slower than baseline (allows jitter)

/** Rough body-similarity by length ratio — good enough to tell "same page" from "different page". */
function similar(a: string, b: string): boolean {
  if (a === b) return true;
  const la = a.length, lb = b.length;
  if (la === 0 && lb === 0) return true;
  return Math.min(la, lb) / Math.max(la, lb, 1) > 0.95;
}

// ── detectors (pure) ────────────────────────────────────────────────────────────────────────────────

export async function detectSqlError(baseline: Probe, prober: Prober): Promise<InjectionHit | null> {
  const p = await prober("'");
  if (SQL_ERROR.test(p.body) && !SQL_ERROR.test(baseline.body)) {
    return { kind: 'sqli', severity: 'high', detail: 'a single quote triggers a database error (error-based SQL injection)', evidence: (p.body.match(SQL_ERROR)?.[0] || '').slice(0, 120) };
  }
  return null;
}

export async function detectSqlBoolean(baseline: Probe, prober: Prober): Promise<InjectionHit | null> {
  const truthy = await prober("' AND '1'='1");
  const falsy = await prober("' AND '1'='2");
  if (SQL_ERROR.test(truthy.body) || SQL_ERROR.test(falsy.body)) return null; // error-based handles this
  if (truthy.status === baseline.status && similar(truthy.body, baseline.body) && !similar(falsy.body, baseline.body)) {
    return { kind: 'sqli', severity: 'high', detail: 'boolean condition changes the response (blind boolean-based SQL injection)', evidence: `true≈baseline (${truthy.body.length}b), false differs (${falsy.body.length}b)` };
  }
  return null;
}

export async function detectSqlTime(baseline: Probe, prober: Prober): Promise<InjectionHit | null> {
  for (const payload of [`' AND SLEEP(${TIME_MS})-- -`, `'; SELECT pg_sleep(${TIME_MS})-- -`, `' OR SLEEP(${TIME_MS})-- -`]) {
    const p = await prober(payload);
    if (p.ms - baseline.ms > TIME_THRESHOLD_MS) {
      return { kind: 'sqli', severity: 'high', detail: 'a time-delay payload measurably slows the response (blind time-based SQL injection)', evidence: `${p.ms}ms vs baseline ${baseline.ms}ms with SLEEP(${TIME_MS})` };
    }
  }
  return null;
}

const SSTI_PAYLOADS = ['{{7*7}}', '${7*7}', '#{7*7}', '<%= 7*7 %>', '{{7*"7"}}'];
export async function detectSsti(prober: Prober): Promise<InjectionHit | null> {
  const marker = 'vtaSS';
  for (const expr of SSTI_PAYLOADS) {
    const p = await prober(marker + expr);
    // Template evaluated 7*7 → the marker is now adjacent to 49 (and the raw expression is gone).
    if (p.body.includes(marker + '49') && !p.body.includes(marker + expr)) {
      return { kind: 'ssti', severity: 'high', detail: `server-side template injection — ${expr} evaluated to 49`, evidence: `${marker}49 reflected` };
    }
  }
  return null;
}

export async function detectCmdTime(baseline: Probe, prober: Prober): Promise<InjectionHit | null> {
  for (const payload of [`; sleep ${TIME_MS}`, `| sleep ${TIME_MS}`, `& sleep ${TIME_MS}`, `$(sleep ${TIME_MS})`, `\`sleep ${TIME_MS}\``]) {
    const p = await prober(payload);
    if (p.ms - baseline.ms > TIME_THRESHOLD_MS) {
      return { kind: 'cmdi', severity: 'high', detail: 'a shell time-delay payload measurably slows the response (OS command injection)', evidence: `${p.ms}ms vs baseline ${baseline.ms}ms with "${payload}"` };
    }
  }
  return null;
}

const TRAVERSAL_PAYLOADS = ['../../../../../../etc/passwd', '....//....//....//....//etc/passwd', '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'];
export async function detectTraversal(baseline: Probe, prober: Prober): Promise<InjectionHit | null> {
  if (PASSWD.test(baseline.body)) return null;
  for (const payload of TRAVERSAL_PAYLOADS) {
    const p = await prober(payload);
    if (PASSWD.test(p.body)) {
      return { kind: 'traversal', severity: 'high', detail: 'path traversal — /etc/passwd contents returned', evidence: (p.body.match(PASSWD)?.[0] || '').slice(0, 80) };
    }
  }
  return null;
}

/** Run every detector against one (baseline, prober); return the hits found. */
export async function runDetectors(baseline: Probe, prober: Prober): Promise<InjectionHit[]> {
  const hits: InjectionHit[] = [];
  const err = await detectSqlError(baseline, prober); if (err) hits.push(err);
  if (!err) { const b = await detectSqlBoolean(baseline, prober); if (b) hits.push(b); }
  const t = await detectSqlTime(baseline, prober); if (t && !hits.some((h) => h.kind === 'sqli')) hits.push(t);
  const s = await detectSsti(prober); if (s) hits.push(s);
  const c = await detectCmdTime(baseline, prober); if (c) hits.push(c);
  const tr = await detectTraversal(baseline, prober); if (tr) hits.push(tr);
  return hits;
}

const KIND_META: Record<InjectionHit['kind'], { title: string; fix: string }> = {
  sqli: { title: 'SQL injection', fix: 'Use parameterized queries / prepared statements (never string-concatenate user input into SQL).' },
  ssti: { title: 'Server-side template injection', fix: 'Never render user input as a template; use a sandboxed/logic-less template and pass data as variables.' },
  cmdi: { title: 'OS command injection', fix: 'Never pass user input to a shell; use argument arrays / safe APIs and validate against an allow-list.' },
  traversal: { title: 'Path traversal', fix: 'Resolve and confine file paths to an allow-listed base directory; reject ../ sequences and absolute paths.' },
};

/**
 * Authorized, non-destructive active injection scan. Builds the coverage map, then tests each GET
 * query parameter with the detector suite. Returns [] unless opts.authorizedActive is set.
 */
export async function activeInjectionScan(ctx: ScanContext): Promise<Finding[]> {
  if (!ctx.opts.authorizedActive) return [];
  const out: Finding[] = [];
  const map = await buildCoverageMap(ctx.baseUrl, { extraHeaders: ctx.opts.extraHeaders, maxPages: ctx.opts.maxCrawl ?? 40, timeoutMs: ctx.opts.timeoutMs });

  // Real endpoint+param pairs from the crawl, plus the seed's own params.
  const urls = new Set<string>(map.paramUrls);
  try { if (new URL(ctx.baseUrl).search) urls.add(ctx.baseUrl); } catch { /* ignore */ }

  const targets: { url: string; param: string }[] = [];
  for (const u of urls) {
    let parsed: URL; try { parsed = new URL(u); } catch { continue; }
    for (const param of parsed.searchParams.keys()) targets.push({ url: u, param });
    if (targets.length >= 40) break; // bound the active surface
  }

  const tested = new Set<string>();
  for (const { url, param } of targets.slice(0, 40)) {
    const key = new URL(url).pathname + '|' + param;
    if (tested.has(key)) continue;
    tested.add(key);

    const prober: Prober = async (value) => {
      const u = new URL(url);
      u.searchParams.set(param, value);
      const t0 = Date.now();
      const res = await safeFetch(u.toString(), { redirect: 'manual', headers: ctx.opts.extraHeaders }, ctx.opts.timeoutMs);
      const ms = Date.now() - t0;
      const body = res ? (await res.text().catch(() => '')).slice(0, 20000) : '';
      return { status: res?.status ?? 0, body, ms };
    };
    const baseline = await prober('vtaBaseline1');
    if (baseline.status === 0) continue; // unreachable
    const hits = await runDetectors(baseline, prober);
    for (const h of hits) {
      const meta = KIND_META[h.kind];
      out.push(f(`inject.${h.kind}.${param}`, `${meta.title} via ?${param}`, h.severity, false,
        `[${new URL(url).pathname}] ${h.detail} — ${h.evidence}`, meta.fix));
    }
  }

  if (!out.length) out.push(f('inject.none', 'No injection found on tested parameters', 'info', true, `tested ${tested.size} parameter(s) with SQLi/SSTI/cmd/traversal probes`));
  return out;
}
