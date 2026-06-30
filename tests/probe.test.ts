// tests/probe.test.ts — self-tests via node:test against tiny local servers.
// Imports the BUILT artifact (dist) so we test exactly what ships; `npm test` builds first.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { probe, summarize } from '../dist/probe.js';
import { scanSecrets, html as H } from '../dist/core.js';
import { checkSecurityHeaders, checkCookieFlags, idorProbe } from '../dist/testkit.js';

function server(handler: http.RequestListener): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const s = http.createServer(handler);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address() as any;
      resolve({ url: `http://127.0.0.1:${addr.port}`, close: () => s.close() });
    });
  });
}

// ── security (back-compat) ─────────────────────────────────────────────────
test('probe flags a wide-open server (missing headers, no security.txt)', async () => {
  const srv = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><body>hi</body></html>'); });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(summarize(findings).failed > 0, 'should have failures');
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
      'content-type': 'text/html',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'x-frame-options': 'SAMEORIGIN',
      'content-security-policy': "default-src 'self'",
    });
    res.end('<html><body>hi</body></html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'header.content-security-policy' && f.pass), 'CSP passes');
  assert.ok(findings.find((f) => f.id === 'securitytxt' && f.pass), 'security.txt passes');
});

// ── secrets ────────────────────────────────────────────────────────────────
test('scanSecrets catches real keys, ignores publishable/anon, redacts', () => {
  const hits = scanSecrets(`
    const stripe = "sk_live_51HxYzAbCdEfGhIjKlMnOpQrStUvWx";
    const aws = "AKIAIOSFODNN7EXAMPLE";
    const pk = "-----BEGIN RSA PRIVATE KEY-----";
    const publishable = "pk_live_thisIsPublishableAndFine";
  `);
  assert.ok(hits.some((h) => h.ruleId === 'stripe.sk_live'), 'catches sk_live');
  assert.ok(hits.some((h) => h.ruleId === 'aws.akid'), 'catches AWS key');
  assert.ok(hits.some((h) => h.ruleId === 'privatekey'), 'catches private key block');
  assert.ok(!hits.some((h) => h.sample.includes('pk_live')), 'ignores publishable pk_live');
  assert.ok(hits.every((h) => !h.sample.includes('UvWx') || h.sample.includes('…')), 'redacts the secret body');
  assert.equal(scanSecrets('const x = 1; fetch("/api");').length, 0, 'clean code => no hits');
});

test('Supabase service_role JWT fires only on role=service_role', () => {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = 'eyJhbGciOiJIUzI1NiJ9';
  const svc = `${head}.${b64({ role: 'service_role' })}.sigaaaaaaaaaa`;
  const anon = `${head}.${b64({ role: 'anon' })}.sigaaaaaaaaaa`;
  assert.ok(scanSecrets(svc).some((h) => h.ruleId === 'supabase.service_role'), 'flags service_role');
  assert.ok(!scanSecrets(anon).some((h) => h.ruleId === 'supabase.service_role'), 'ignores anon');
});

test('probe surfaces a secret leaked in a same-origin script bundle', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/app.js') { res.writeHead(200, { 'content-type': 'application/javascript' }); res.end('var k="sk_live_AbCdEfGhIjKlMnOpQrStUvWx";'); return; }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body><script src="/app.js"></script></body></html>');
  });
  const findings = await probe(srv.url, { only: ['secrets'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'secret.stripe.sk_live' && !f.pass), 'flags the leaked key from the bundle');
});

// ── exposure (SPA false-positive guard) ──────────────────────────────────────
test('exposure does NOT false-positive when a SPA returns index.html for /.env', async () => {
  const srv = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!DOCTYPE html><html><body>app</body></html>'); });
  const findings = await probe(srv.url, { only: ['exposure'] });
  srv.close();
  assert.ok(!findings.some((f) => f.id.startsWith('exposed/') && !f.pass), 'no exposed-file findings for an SPA catch-all');
});

test('exposure flags a genuinely served .env', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/.env') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('DATABASE_URL=postgres://u:p@h/db\nSTRIPE_KEY=sk_test_x\n'); return; }
    res.writeHead(404); res.end('nope');
  });
  const findings = await probe(srv.url, { only: ['exposure'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'exposed/.env' && !f.pass), 'flags a real .env');
});

// ── seo + a11y (HTML parsing) ────────────────────────────────────────────────
test('seo + a11y findings reflect the served HTML', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<!DOCTYPE html><html lang="en"><head><title>My App</title><meta name="viewport" content="width=device-width"></head><body><h1>Hi</h1><img src="/a.png"></body></html>');
  });
  const findings = await probe(srv.url, { only: ['seo', 'a11y'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'seo.title' && f.pass), 'detects title');
  assert.ok(findings.find((f) => f.id === 'seo.description' && !f.pass), 'flags missing description');
  assert.ok(findings.find((f) => f.id === 'a11y.lang' && f.pass), 'detects lang');
  assert.ok(findings.find((f) => f.id === 'a11y.alt' && !f.pass), 'flags img missing alt');
});

test('html helpers parse tags correctly', () => {
  const doc = '<html lang="en"><title>T</title><img src="/x.png" alt="x"><img src="/y.png"><a href="/p">p</a><script src="/b.js"></script>';
  assert.equal(H.title(doc), 'T');
  assert.equal(H.hasLang(doc), true);
  assert.equal(H.images(doc).filter((i) => !i.hasAlt).length, 1);
  assert.deepEqual(H.scripts(doc), ['/b.js']);
  assert.deepEqual(H.links(doc), ['/p']);
});

// ── white-box helpers (unchanged) ────────────────────────────────────────────
test('checkSecurityHeaders + checkCookieFlags', () => {
  assert.deepEqual(checkSecurityHeaders({ 'strict-transport-security': 'max-age=99999', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'content-security-policy': "default-src 'self'" }), []);
  assert.ok(checkSecurityHeaders({}).length >= 3);
  assert.deepEqual(checkCookieFlags('s=1; Secure; HttpOnly; SameSite=Lax'), []);
  assert.ok(checkCookieFlags('s=1').length === 3);
});

test('idorProbe reports a cross-tenant leak', async () => {
  const leaky = await server((_req, res) => { res.writeHead(200); res.end('secret'); });
  const res = await idorProbe(
    { label: 'attacker', headers: {} },
    [{ name: 'GET /orgA/secret', request: () => ({ url: leaky.url + '/orgA/secret' }) }],
  );
  leaky.close();
  assert.equal(res[0].ok, false, 'a 200 to the attacker is a leak');
});
