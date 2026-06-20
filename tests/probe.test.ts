// tests/probe.test.ts — self-tests via node:test against a tiny local server.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { probe, summarize } from '../src/probe.ts';
import { checkSecurityHeaders, checkCookieFlags, idorProbe } from '../src/testkit.ts';
import { runNpmAudit, failsAtLevel } from '../src/audit.ts';

function server(handler: http.RequestListener): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const s = http.createServer(handler);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address() as any;
      resolve({ url: `http://127.0.0.1:${addr.port}`, close: () => s.close() });
    });
  });
}

test('probe flags a wide-open server (missing headers, no security.txt)', async () => {
  const srv = await server((_req, res) => { res.writeHead(200); res.end('hi'); });
  const findings = await probe(srv.url);
  srv.close();
  const sum = summarize(findings);
  assert.ok(sum.failed > 0, 'should have failures');
  assert.ok(findings.find((f) => f.id === 'header.x-content-type-options' && !f.pass), 'flags missing nosniff');
  assert.ok(findings.find((f) => f.id === 'securitytxt' && !f.pass), 'flags missing security.txt');
  assert.ok(findings.find((f) => f.id === 'tls.scheme' && !f.pass), 'flags non-https');
});

test('probe passes a hardened server', async () => {
  const srv = await server((req, res) => {
    if (req.url?.startsWith('/.well-known/security.txt')) {
      res.writeHead(200); res.end('Contact: mailto:s@x.com\nExpires: 2027-01-01T00:00:00Z\n'); return;
    }
    res.writeHead(200, {
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'x-frame-options': 'SAMEORIGIN',
      'content-security-policy': "default-src 'self'",
    });
    res.end('hi');
  });
  const findings = await probe(srv.url);
  srv.close();
  assert.ok(findings.find((f) => f.id === 'header.content-security-policy' && f.pass), 'CSP passes');
  assert.ok(findings.find((f) => f.id === 'securitytxt' && f.pass), 'security.txt passes');
});

test('checkSecurityHeaders + checkCookieFlags', () => {
  assert.deepEqual(checkSecurityHeaders({ 'strict-transport-security': 'max-age=99999', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'content-security-policy': "default-src 'self'" }), []);
  assert.ok(checkSecurityHeaders({}).length >= 3);
  assert.deepEqual(checkCookieFlags('s=1; Secure; HttpOnly; SameSite=Lax'), []);
  assert.ok(checkCookieFlags('s=1').length === 3);
});

test('flags an exposed .git/HEAD (real signature) but not a SPA 200 fallback', async () => {
  const exposed = await server((req, res) => {
    if (req.url === '/.git/HEAD') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('ref: refs/heads/main\n'); return; }
    res.writeHead(200); res.end('x');
  });
  const f1 = await probe(exposed.url);
  exposed.close();
  assert.ok(f1.find((f) => f.id === '/.git/HEAD'.replace(/^/, 'exposure') && !f.pass), 'exposed .git/HEAD flagged');

  const spa = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!doctype html><html>app</html>'); });
  const f2 = await probe(spa.url);
  spa.close();
  assert.ok(!f2.find((f) => f.id.startsWith('exposure')), 'SPA html fallback is NOT a false positive');
});

test('flags an exposed source map referenced by the page', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<script src="/app.js"></script>'); return; }
    if (req.url === '/app.js.map') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"version":3,"sources":["a.ts"]}'); return; }
    res.writeHead(404); res.end();
  });
  const f = await probe(srv.url);
  srv.close();
  assert.ok(f.find((x) => x.id === 'sourcemaps' && !x.pass), 'exposed source map flagged');
});

test('npm audit wrapper runs and reports counts (kit has no vuln deps)', async () => {
  const r = await runNpmAudit(process.cwd());
  assert.equal(typeof r.total, 'number');
  assert.equal(failsAtLevel(r, 'high'), (r.counts.high ?? 0) + (r.counts.critical ?? 0) > 0);
});

test('flags an open redirect via a common param', async () => {
  const srv = await server((req, res) => {
    const u = new URL(req.url!, 'http://x');
    const next = u.searchParams.get('next');
    if (next) { res.writeHead(302, { location: next }); res.end(); return; }
    res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>ok</html>');
  });
  const f = await probe(srv.url);
  srv.close();
  assert.ok(f.find((x) => x.id === 'open-redirect' && !x.pass), 'open redirect flagged');
});

test('flags a cross-origin script without SRI', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<script src="https://cdn.example.com/x.js"></script>');
  });
  const f = await probe(srv.url);
  srv.close();
  assert.ok(f.find((x) => x.id === 'sri' && !x.pass), 'missing SRI flagged');
});

test('rate-limit check passes when a burst is throttled (429)', async () => {
  let n = 0;
  const srv = await server((_req, res) => { n++; res.writeHead(n > 3 ? 429 : 200); res.end(); });
  const f = await probe(srv.url, { rateLimitPath: '/api/x' });
  srv.close();
  assert.ok(f.find((x) => x.id === 'rate-limit' && x.pass), 'rate limiting detected');
});

test('idorProbe reports a cross-tenant leak', async () => {
  // Server that (wrongly) returns 200 regardless of who asks → simulates an IDOR hole.
  const leaky = await server((_req, res) => { res.writeHead(200); res.end('secret'); });
  const res = await idorProbe(
    { label: 'attacker', headers: {} },
    [{ name: 'GET /orgA/secret', request: () => ({ url: leaky.url + '/orgA/secret' }) }],
  );
  leaky.close();
  assert.equal(res[0].ok, false, 'a 200 to the attacker is a leak');
});
