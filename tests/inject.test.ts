/**
 * #43 — active injection engine. Unit-tests each detector with stub probers (fast, no real sleeps) and
 * runs the full scan against a deliberately-vulnerable fixture + a safe fixture (no false positives).
 * Confirms the whole engine is gated behind opts.authorizedActive.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  detectSqlError, detectSqlBoolean, detectSqlTime, detectSsti, detectCmdTime, detectTraversal,
  activeInjectionScan,
} from '../dist/inject.js';
import { startServer } from './helpers/http-fixture.ts';
import type { Probe, Prober } from '../dist/inject.js';
import type { ScanContext, Finding } from '../dist/types.js';

const P = (body: string, ms = 40, status = 200): Probe => ({ body, ms, status });
const anyFail = (fs: Finding[], prefix: string) => fs.some((f) => !f.pass && f.id.startsWith(prefix));

test('detectSqlError: DB error on a quote when baseline is clean', async () => {
  const base = P('normal page');
  const prober: Prober = async () => P("You have an error in your SQL syntax near '''");
  assert.ok(await detectSqlError(base, prober));
  // clean server → no hit
  assert.equal(await detectSqlError(base, async () => P('still normal')), null);
});

test('detectSqlBoolean: true≈baseline, false differs', async () => {
  const base = P('A'.repeat(1000));
  const prober: Prober = async (v) => (v.includes("'1'='1") ? P('A'.repeat(1000)) : P('empty'));
  assert.ok(await detectSqlBoolean(base, prober));
});

test('detectSqlTime + detectCmdTime: measurable delay flags', async () => {
  const base = P('x', 40);
  assert.ok(await detectSqlTime(base, async (v) => (/SLEEP|pg_sleep/i.test(v) ? P('x', 3200) : P('x', 45))));
  assert.ok(await detectCmdTime(base, async (v) => (/sleep/.test(v) ? P('x', 3200) : P('x', 45))));
  // constant-time server → no hit
  assert.equal(await detectSqlTime(base, async () => P('x', 45)), null);
});

test('detectSsti: 7*7 evaluates to 49 adjacent to the marker', async () => {
  const prober: Prober = async (v) => P(v.includes('{{7*7}}') ? 'result: vtaSS49 done' : `echo ${v}`);
  assert.ok(await detectSsti(prober));
  assert.equal(await detectSsti(async (v) => P(`echo ${v}`)), null); // pure echo → no eval
});

test('detectTraversal: /etc/passwd contents returned', async () => {
  const base = P('home');
  assert.ok(await detectTraversal(base, async (v) => P(v.includes('passwd') ? 'root:x:0:0:root:/root:/bin/bash' : 'home')));
});

// ── integration ──────────────────────────────────────────────────────────────────────────────────
function vulnHandler(): http.RequestListener {
  return (req, res) => {
    const url = new URL(req.url || '/', 'http://fixture.local');
    if (url.pathname === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(`<a href="/item?id=1">item</a>`); return; }
    if (url.pathname === '/item') {
      const id = url.searchParams.get('id') || '';
      if (id.includes("'")) { res.writeHead(500, { 'content-type': 'text/html' }); res.end("You have an error in your SQL syntax; check the manual near '''"); return; }
      if (id.includes('passwd')) { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('root:x:0:0:root:/root:/bin/bash\n'); return; }
      res.writeHead(200, { 'content-type': 'text/html' }); res.end(`<p>item ${id.replace(/[<>]/g, '')}</p>`); return;
    }
    res.writeHead(404); res.end('nf');
  };
}

const ctxFor = (baseUrl: string): ScanContext => ({ baseUrl, opts: { authorizedActive: true, maxCrawl: 20, timeoutMs: 8000 } } as ScanContext);

test('inject: engine is gated — returns [] without authorizedActive', async () => {
  const findings = await activeInjectionScan({ baseUrl: 'https://x.test', opts: {} } as ScanContext);
  assert.equal(findings.length, 0);
});

test('inject: flags SQLi + traversal on a vulnerable fixture param', async () => {
  const srv = await startServer(vulnHandler());
  try {
    const findings = await activeInjectionScan(ctxFor(srv.url));
    assert.ok(anyFail(findings, 'inject.sqli'), `expected inject.sqli, got: ${findings.map((f) => f.id).join(',')}`);
    assert.ok(anyFail(findings, 'inject.traversal'), `expected inject.traversal, got: ${findings.map((f) => f.id).join(',')}`);
    assert.ok(findings.find((f) => f.id.startsWith('inject.sqli'))!.detail.includes('/item'));
  } finally { await srv.close(); }
});

test('inject: no false positives on a safe fixture (inject.none)', async () => {
  const safe: http.RequestListener = (req, res) => {
    const url = new URL(req.url || '/', 'http://fixture.local');
    if (url.pathname === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(`<a href="/item?id=1">item</a>`); return; }
    // Safe: parameterized — always the same clean page regardless of id, no errors, no file contents.
    res.writeHead(200, { 'content-type': 'text/html' }); res.end('<p>a product</p>');
  };
  const srv = await startServer(safe);
  try {
    const findings = await activeInjectionScan(ctxFor(srv.url));
    assert.ok(!findings.some((f) => !f.pass), `unexpected injection FP: ${findings.filter((f) => !f.pass).map((f) => f.id).join(',')}`);
    assert.ok(findings.some((f) => f.id === 'inject.none'));
  } finally { await srv.close(); }
});
