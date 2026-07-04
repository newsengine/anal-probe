// tests/plugins.test.ts — self-tests for the JSON plugin/template engine (src/plugins.ts).
// Imports the BUILT artifact (dist) so we test exactly what ships; `npm test` builds first.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  validateTemplate, evaluateTemplate, evaluateMatcher, pluginChecks,
} from '../dist/plugins.js';

// Tiny local http server (copied from tests/probe.test.ts to keep this file self-contained).
function server(handler: http.RequestListener): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const s = http.createServer(handler);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address() as any;
      resolve({ url: `http://127.0.0.1:${addr.port}`, close: () => s.close() });
    });
  });
}

const goodTemplate = {
  id: 'x-powered-by',
  title: 'X-Powered-By discloses stack',
  severity: 'low',
  request: { path: '/', method: 'GET' },
  'matchers-condition': 'and',
  matchers: [{ type: 'header', name: 'x-powered-by', regex: '.+' }],
  fix: 'Remove the header.',
  owasp: 'A05',
  cwe: ['CWE-200'],
};

// ── validateTemplate ───────────────────────────────────────────────────────
test('validateTemplate accepts a well-formed template', () => {
  const v = validateTemplate(goodTemplate);
  assert.equal(v.ok, true, v.errors.join('; '));
  assert.equal(v.errors.length, 0);
});

test('validateTemplate rejects non-objects and arrays', () => {
  assert.equal(validateTemplate(null).ok, false);
  assert.equal(validateTemplate('nope').ok, false);
  assert.equal(validateTemplate([goodTemplate]).ok, false);
});

test('validateTemplate rejects missing id/title/severity', () => {
  assert.equal(validateTemplate({ ...goodTemplate, id: '' }).ok, false);
  assert.equal(validateTemplate({ ...goodTemplate, title: undefined }).ok, false);
  assert.equal(validateTemplate({ ...goodTemplate, severity: 'critical' }).ok, false);
});

test('validateTemplate rejects a non-GET/HEAD method', () => {
  const v = validateTemplate({ ...goodTemplate, request: { path: '/', method: 'POST' } });
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e: string) => /GET or HEAD/.test(e)));
});

test('validateTemplate rejects bad request.path', () => {
  assert.equal(validateTemplate({ ...goodTemplate, request: { path: 'no-slash' } }).ok, false);
  assert.equal(validateTemplate({ ...goodTemplate, request: {} }).ok, false);
});

test('validateTemplate rejects empty / malformed matchers', () => {
  assert.equal(validateTemplate({ ...goodTemplate, matchers: [] }).ok, false);
  assert.equal(validateTemplate({ ...goodTemplate, matchers: [{ type: 'nope' }] }).ok, false);
  assert.equal(validateTemplate({ ...goodTemplate, matchers: [{ type: 'status' }] }).ok, false);
  assert.equal(validateTemplate({ ...goodTemplate, matchers: [{ type: 'body-contains' }] }).ok, false);
  assert.equal(validateTemplate({ ...goodTemplate, matchers: [{ type: 'body-regex', regex: '(' }] }).ok, false);
  assert.equal(validateTemplate({ ...goodTemplate, matchers: [{ type: 'header' }] }).ok, false);
});

test('validateTemplate rejects an invalid matchers-condition', () => {
  assert.equal(validateTemplate({ ...goodTemplate, 'matchers-condition': 'maybe' }).ok, false);
});

// ── evaluateMatcher / evaluateTemplate ──────────────────────────────────────
const view = (over: Partial<{ status: number; headers: Record<string, string>; body: string }> = {}) => ({
  status: over.status ?? 200,
  headers: over.headers ?? {},
  body: over.body ?? '',
});

test('evaluateMatcher: status equals and status-in-list', () => {
  assert.equal(evaluateMatcher({ type: 'status', status: 200 } as any, view()), true);
  assert.equal(evaluateMatcher({ type: 'status', status: 404 } as any, view()), false);
  assert.equal(evaluateMatcher({ type: 'status', status: [200, 204] } as any, view({ status: 204 })), true);
  assert.equal(evaluateMatcher({ type: 'status', status: [301, 302] } as any, view({ status: 200 })), false);
});

test('evaluateMatcher: header presence, regex, contains, equals, negative', () => {
  const h = view({ headers: { 'x-powered-by': 'Express' } });
  assert.equal(evaluateMatcher({ type: 'header', name: 'x-powered-by' } as any, h), true);
  assert.equal(evaluateMatcher({ type: 'header', name: 'X-Powered-By', regex: 'Expr' } as any, h), true);
  assert.equal(evaluateMatcher({ type: 'header', name: 'x-powered-by', contains: 'press' } as any, h), true);
  assert.equal(evaluateMatcher({ type: 'header', name: 'x-powered-by', equals: 'express' } as any, h), true);
  assert.equal(evaluateMatcher({ type: 'header', name: 'x-powered-by', equals: 'nginx' } as any, h), false);
  // absent header
  assert.equal(evaluateMatcher({ type: 'header', name: 'server' } as any, h), false);
  // negative: header absent → matches
  assert.equal(evaluateMatcher({ type: 'header', name: 'server', negative: true } as any, h), true);
});

test('evaluateMatcher: body-contains and body-regex (with flags)', () => {
  const b = view({ body: 'Fatal error: DEBUG=TRUE at line 3' });
  assert.equal(evaluateMatcher({ type: 'body-contains', contains: 'Fatal error' } as any, b), true);
  assert.equal(evaluateMatcher({ type: 'body-contains', contains: 'nope' } as any, b), false);
  assert.equal(evaluateMatcher({ type: 'body-regex', regex: 'debug=true', flags: 'i' } as any, b), true);
  assert.equal(evaluateMatcher({ type: 'body-regex', regex: 'debug=true' } as any, b), false);
});

test('evaluateTemplate: AND requires all matchers', () => {
  const t = { ...goodTemplate, 'matchers-condition': 'and', matchers: [
    { type: 'status', status: 200 }, { type: 'header', name: 'x-powered-by' },
  ] };
  assert.equal(evaluateTemplate(t as any, view({ headers: { 'x-powered-by': 'PHP' } })), true);
  assert.equal(evaluateTemplate(t as any, view({ status: 500, headers: { 'x-powered-by': 'PHP' } })), false);
  assert.equal(evaluateTemplate(t as any, view()), false); // header missing
});

test('evaluateTemplate: OR needs only one matcher', () => {
  const t = { ...goodTemplate, 'matchers-condition': 'or', matchers: [
    { type: 'status', status: 500 }, { type: 'body-contains', contains: 'stack trace' },
  ] };
  assert.equal(evaluateTemplate(t as any, view({ body: 'a stack trace here' })), true);
  assert.equal(evaluateTemplate(t as any, view({ status: 500 })), true);
  assert.equal(evaluateTemplate(t as any, view()), false);
});

test('evaluateTemplate: defaults to AND when no matchers-condition', () => {
  const t = { ...goodTemplate, matchers: [{ type: 'status', status: 200 }, { type: 'status', status: 404 }] };
  delete (t as any)['matchers-condition'];
  assert.equal(evaluateTemplate(t as any, view()), false);
});

// ── integration: pluginChecks against a local server ────────────────────────
test('pluginChecks runs templates from a dir: one matches, one does not', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/') {
      res.writeHead(200, { 'content-type': 'text/html', 'x-powered-by': 'Express' });
      res.end('<html>hi</html>');
    } else {
      res.writeHead(404); res.end('not found');
    }
  });
  const dir = mkdtempSync(path.join(tmpdir(), 'anal-probe-plugins-'));
  // Matches: root returns X-Powered-By.
  writeFileSync(path.join(dir, 'hit.json'), JSON.stringify({
    id: 'xpb', title: 'X-Powered-By present', severity: 'low',
    request: { path: '/', method: 'GET' },
    matchers: [{ type: 'header', name: 'x-powered-by', regex: '.+' }],
    fix: 'remove it', owasp: 'A05', cwe: ['CWE-200'],
  }));
  // Does NOT match: /nope is a 404, expects 200.
  writeFileSync(path.join(dir, 'miss.json'), JSON.stringify({
    id: 'miss', title: 'Should not fire', severity: 'high',
    request: { path: '/nope' },
    matchers: [{ type: 'status', status: 200 }],
  }));
  // A garbage file: must be skipped, not crash, and reported as info.
  writeFileSync(path.join(dir, 'broken.json'), '{ not valid json');
  // A non-json file: must be ignored entirely.
  writeFileSync(path.join(dir, 'notes.txt'), 'ignore me');

  const ctx: any = { origin: srv.url, url: new URL(srv.url), opts: { pluginsDir: dir } };
  const findings = await pluginChecks(ctx);
  srv.close();
  rmSync(dir, { recursive: true, force: true });

  const hit = findings.find((f) => f.id === 'plugins.xpb');
  assert.ok(hit && !hit.pass, 'matching template should emit a failing finding');
  assert.match(hit!.detail, /OWASP A05/);
  assert.equal(findings.find((f) => f.id === 'plugins.miss'), undefined, 'non-matching template emits nothing');
  assert.ok(findings.find((f) => f.id.startsWith('plugins.invalid.') && f.pass), 'broken template reported as info');
  const loaded = findings.find((f) => f.id === 'plugins.loaded');
  assert.ok(loaded && loaded.pass, 'summary finding present');
  assert.match(loaded!.detail, /2 template\(s\)/); // hit + miss valid; broken skipped
});

test('pluginChecks emits plugins.none when the directory is absent', async () => {
  const ctx: any = { origin: 'http://127.0.0.1:1', url: new URL('http://127.0.0.1:1'), opts: { pluginsDir: '/no/such/dir/anal-probe' } };
  const findings = await pluginChecks(ctx);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'plugins.none');
  assert.equal(findings[0].pass, true);
});
