// tests/probe.test.ts — self-tests via node:test against tiny local servers.
// Imports the BUILT artifact (dist) so we test exactly what ships; `npm test` builds first.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { probe, summarize, normalizeUrl } from '../dist/probe.js';
import { scanSecrets, html as H } from '../dist/core.js';
import { checkSecurityHeaders, checkCookieFlags, idorProbe } from '../dist/testkit.js';
import { failsAtLevel } from '../dist/audit.js';
import { lintCsp } from '../dist/checks.js';
import { toSarif } from '../dist/sarif.js';
import { buildBaseline, applyBaseline } from '../dist/baseline.js';
import { evaluateDnsHygiene, apexOf } from '../dist/dns.js';

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

// ── ported security checks (open-redirect / sri / cookie-prefix / rate-limit) ─
test('open-redirect: flags a server that 3xx-es a redirect param off-domain', async () => {
  const srv = await server((req, res) => {
    const u = new URL(req.url || '/', 'http://x');
    const next = u.searchParams.get('next');
    if (next) { res.writeHead(302, { location: next }); res.end(); return; }
    res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'open-redirect' && !f.pass), 'flags the open redirect');
});

test('sri: flags a cross-origin script with no integrity, passes when pinned', async () => {
  const unpinned = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><script src="https://cdn.example.com/x.js"></script></html>'); });
  const a = await probe(unpinned.url, { only: ['security'] }); unpinned.close();
  assert.ok(a.find((f) => f.id === 'sri' && !f.pass), 'flags un-pinned cross-origin script');

  const pinned = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><script src="https://cdn.example.com/x.js" integrity="sha384-abc" crossorigin></script></html>'); });
  const b = await probe(pinned.url, { only: ['security'] }); pinned.close();
  assert.ok(b.find((f) => f.id === 'sri' && f.pass), 'passes when integrity is present');
});

test('cookie-prefix: info-fails on an un-prefixed cookie', async () => {
  const srv = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'sid=abc; Secure; HttpOnly; SameSite=Lax' }); res.end('<html>ok</html>'); });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'cookie.sid' && f.pass), 'cookie flags pass');
  assert.ok(findings.find((f) => f.id === 'cookie-prefix.sid' && !f.pass), 'recommends a __Host-/__Secure- prefix');
});

test('rate-limit (opt-in): passes when the path throttles with 429', async () => {
  let n = 0;
  const srv = await server((_req, res) => { n++; if (n > 5) { res.writeHead(429); res.end('slow down'); return; } res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>ok</html>'); });
  const findings = await probe(srv.url, { only: ['security'], rateLimitPath: '/' });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'rate-limit' && f.pass), 'detects throttling');
});

// ── dependency audit (pure severity gating) ──────────────────────────────────
test('audit failsAtLevel gates at/above the threshold', () => {
  assert.equal(failsAtLevel({ counts: { high: 1 }, total: 1 }, 'high'), true, 'high vuln fails at high');
  assert.equal(failsAtLevel({ counts: { low: 2 }, total: 2 }, 'high'), false, 'low vuln does not fail at high');
  assert.equal(failsAtLevel({ counts: { low: 2 }, total: 2 }, 'low'), true, 'low vuln fails at low');
  assert.equal(failsAtLevel({ counts: {}, total: 0 }, 'high'), false, 'clean audit passes');
});

// ── CSP linter (#4) ──────────────────────────────────────────────────────────
test('lintCsp flags unsafe-inline / unsafe-eval / wildcard, passes a strong policy', () => {
  const weak = lintCsp("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *");
  const ids = weak.map((i) => i.id);
  assert.ok(ids.includes('csp.unsafe-inline'), 'flags unsafe-inline');
  assert.ok(ids.includes('csp.unsafe-eval'), 'flags unsafe-eval');
  assert.ok(ids.includes('csp.wildcard-script'), 'flags wildcard script source');

  const strong = lintCsp("default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'");
  assert.deepEqual(strong, [], 'a strong policy has no issues');
});

test('lintCsp: script-src falls back to default-src', () => {
  const issues = lintCsp("default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'");
  assert.ok(issues.some((i) => i.id === 'csp.unsafe-inline'), 'inherits weakness from default-src');
});

test('probe emits csp.* findings when a weak CSP is served', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'content-security-policy': "script-src 'self' 'unsafe-inline'" });
    res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'csp.unsafe-inline' && !f.pass), 'surfaces the CSP weakness');
});

// ── SARIF output (#2) ────────────────────────────────────────────────────────
test('toSarif produces valid 2.1.0 with rules + results for failing findings only', () => {
  const findings = [
    { id: 'header.hsts', category: 'security', title: 'Missing HSTS', severity: 'high', pass: false, detail: 'no HSTS', fix: 'Send HSTS' },
    { id: 'seo.title', category: 'seo', title: 'Has title', severity: 'info', pass: true, detail: 'ok' },
  ] as any;
  const sarif = toSarif(findings, { url: 'https://x.example', version: '1.2.3' }) as any;
  assert.equal(sarif.version, '2.1.0');
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'anal-probe');
  assert.equal(run.tool.driver.version, '1.2.3');
  assert.equal(run.results.length, 1, 'only the failing finding becomes a result');
  assert.equal(run.results[0].ruleId, 'header.hsts');
  assert.equal(run.results[0].level, 'error', 'high maps to error');
  assert.ok(run.tool.driver.rules.some((r: any) => r.id === 'header.hsts'), 'registers the rule');
});

// ── baseline / diff mode (#3) ────────────────────────────────────────────────
test('baseline: buildBaseline records failing keys; applyBaseline splits new vs accepted', () => {
  const findings = [
    { id: 'header.hsts', category: 'security', title: 't', severity: 'high', pass: false, detail: 'd' },
    { id: 'open-redirect', category: 'security', title: 't', severity: 'high', pass: false, detail: 'd' },
    { id: 'seo.title', category: 'seo', title: 't', severity: 'info', pass: true, detail: 'd' },
  ] as any;
  const baseline = buildBaseline(findings, 'https://x');
  assert.deepEqual(baseline.keys, ['header.hsts', 'open-redirect'], 'only failing keys, sorted');

  // A later scan where hsts is still failing (accepted) but a NEW failure appears.
  const later = [
    { id: 'header.hsts', category: 'security', title: 't', severity: 'high', pass: false, detail: 'd' },
    { id: 'sri', category: 'security', title: 't', severity: 'low', pass: false, detail: 'd' },
  ] as any;
  const diff = applyBaseline(later, baseline);
  assert.deepEqual(diff.newFailures.map((f: any) => f.id), ['sri'], 'sri is new');
  assert.deepEqual(diff.baselined.map((f: any) => f.id), ['header.hsts'], 'hsts is accepted');
});

// ── DNS / email hygiene (#6) ─────────────────────────────────────────────────
test('apexOf reduces subdomains to the registrable apex', () => {
  assert.equal(apexOf('beta.example.com'), 'example.com');
  assert.equal(apexOf('example.com'), 'example.com');
  assert.equal(apexOf('a.b.c.example.com'), 'example.com');
});

test('evaluateDnsHygiene: flags a bare domain, passes a hardened one', () => {
  const bare = evaluateDnsHygiene({ hostname: 'x.com', apex: 'x.com', apexTxt: [], dmarcTxt: [], hasCaa: false, danglingCnameTarget: null });
  const byId = (id: string) => bare.find((f: any) => f.id === id);
  assert.ok(byId('dns.spf') && !byId('dns.spf').pass, 'no SPF fails');
  assert.ok(byId('dns.dmarc') && !byId('dns.dmarc').pass, 'no DMARC fails');
  assert.ok(byId('dns.caa') && !byId('dns.caa').pass, 'no CAA fails');

  const hard = evaluateDnsHygiene({
    hostname: 'x.com', apex: 'x.com',
    apexTxt: ['v=spf1 include:_spf.google.com -all'],
    dmarcTxt: ['v=DMARC1; p=reject; rua=mailto:a@x.com'],
    hasCaa: true, danglingCnameTarget: null,
  });
  assert.ok(hard.every((f: any) => f.pass), 'a fully hardened domain has no failures');
});

test('evaluateDnsHygiene: p=none is a weak (failing) DMARC; dangling CNAME is high', () => {
  const weakDmarc = evaluateDnsHygiene({ hostname: 'x.com', apex: 'x.com', apexTxt: ['v=spf1 -all'], dmarcTxt: ['v=DMARC1; p=none'], hasCaa: true, danglingCnameTarget: null });
  const d = weakDmarc.find((f: any) => f.id === 'dns.dmarc');
  assert.ok(d && !d.pass && d.severity === 'low', 'p=none is a low-severity fail');

  const dangling = evaluateDnsHygiene({ hostname: 'gone.x.com', apex: 'x.com', apexTxt: ['v=spf1 -all'], dmarcTxt: ['v=DMARC1; p=reject'], hasCaa: true, danglingCnameTarget: 'old-app.herokudns.com' });
  const c = dangling.find((f: any) => f.id === 'dns.dangling-cname');
  assert.ok(c && !c.pass && c.severity === 'high', 'dangling CNAME is a high-severity takeover risk');
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

// ═══════════════════════ audit fixes (2026-07-02) ═══════════════════════════

// [DNS apex] multi-label public suffixes — the .com.au bug found live on agentaus.com.au.
test('apexOf handles multi-label public suffixes (.com.au / .co.uk / .co.nz)', () => {
  assert.equal(apexOf('agentaus.com.au'), 'agentaus.com.au', 'AU domain apex is the registrable name, not com.au');
  assert.equal(apexOf('www.agentaus.com.au'), 'agentaus.com.au');
  assert.equal(apexOf('shop.example.co.uk'), 'example.co.uk');
  assert.equal(apexOf('foo.bar.example.co.nz'), 'example.co.nz');
  assert.equal(apexOf('plain.example.com'), 'example.com', 'ordinary TLDs still use last two labels');
});

// [correctness #1] open redirect via an UPPERCASE protocol-relative location.
test('open-redirect: catches a protocol-relative redirect regardless of case', async () => {
  const srv = await server((req, res) => {
    const u = new URL(req.url || '/', 'http://x');
    const p = u.searchParams.get('next');
    if (p) { res.writeHead(302, { location: '//EVIL.EXAMPLE/' }); res.end(); return; }
    res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'open-redirect' && !f.pass), 'flags //EVIL.EXAMPLE despite uppercase');
});

// [correctness #2] .env with lowercase variable names (Flask/Django style).
test('exposure flags a .env that uses lowercase variable names', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/.env') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('debug_mode=true\ndatabase_url=postgres://u:p@h/db\n'); return; }
    res.writeHead(404); res.end('nope');
  });
  const findings = await probe(srv.url, { only: ['exposure'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'exposed/.env' && !f.pass), 'lowercase-keyed .env is still detected');
});

// [correctness #15] object-src falls back to default-src 'none'.
test('lintCsp: object-src inherits default-src \'none\' (no false object-src warning)', () => {
  const issues = lintCsp("default-src 'none'; script-src 'self' 'nonce-x'; base-uri 'self'");
  assert.ok(!issues.some((i) => i.id === 'csp.object-src'), "default-src 'none' covers object-src");
  const missing = lintCsp("default-src 'self'; script-src 'self' 'nonce-x'; base-uri 'self'");
  assert.ok(missing.some((i) => i.id === 'csp.object-src'), "default-src 'self' does NOT cover object-src");
});

// [coverage #16/#20/#22] modern hardening headers.
test('security: flags missing Permissions-Policy, COOP, and non-preloadable HSTS', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'strict-transport-security': 'max-age=600' });
    res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'header.permissions-policy' && !f.pass), 'flags missing Permissions-Policy');
  assert.ok(findings.find((f) => f.id === 'header.cross-origin-opener-policy' && !f.pass), 'flags missing COOP');
  assert.ok(findings.find((f) => f.id === 'tls.hsts-preload' && !f.pass), 'short HSTS is not preload-eligible');
});

test('security: HSTS preload-eligible header passes', async () => {
  const srv = await server((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload' });
    res.end('<html>ok</html>');
  });
  const findings = await probe(srv.url, { only: ['security'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'tls.hsts-preload' && f.pass), 'full HSTS is preload-eligible');
});

// [coverage #3] framework debug/admin endpoint exposure.
test('exposure flags a Spring Boot actuator health endpoint', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/actuator/health') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"status":"UP","components":{"db":{"status":"UP"}}}'); return; }
    res.writeHead(404); res.end('nope');
  });
  const findings = await probe(srv.url, { only: ['exposure'] });
  srv.close();
  assert.ok(findings.find((f) => f.id === 'exposed/actuator/health' && !f.pass), 'detects exposed actuator');
});

// [coverage #4] directory listing detection + SPA guard.
test('exposure flags a real directory listing but not an SPA catch-all', async () => {
  const listing = await server((req, res) => {
    if (req.url?.startsWith('/uploads/')) { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>Index of /uploads</title></head><body><pre><a href="../">Parent Directory</a>\n<a href="a.jpg">a.jpg</a></pre></body></html>'); return; }
    res.writeHead(404); res.end('nope');
  });
  const a = await probe(listing.url, { only: ['exposure'] }); listing.close();
  assert.ok(a.find((f) => f.id === 'dir-listing/uploads/' && !f.pass), 'flags an autoindex page');

  const spa = await server((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!DOCTYPE html><html><body><div id="root"></div><script src="/app.js"></script></body></html>'); });
  const b = await probe(spa.url, { only: ['exposure'] }); spa.close();
  assert.ok(!b.some((f) => f.id.startsWith('dir-listing') && !f.pass), 'SPA index is not a directory listing');
});

// [coverage #11/#21] robots.txt disclosing sensitive paths.
test('exposure flags robots.txt that Disallows sensitive paths', async () => {
  const srv = await server((req, res) => {
    if (req.url === '/robots.txt') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('User-agent: *\nDisallow: /admin/\nDisallow: /internal-backup/\nDisallow: /public/\n'); return; }
    res.writeHead(404); res.end('nope');
  });
  const findings = await probe(srv.url, { only: ['exposure'] });
  srv.close();
  const finding = findings.find((f) => f.id === 'robots.sensitive');
  assert.ok(finding && !finding.pass, 'flags admin/backup Disallow entries');
});

// [robustness #7/#14] bare-domain normalization.
test('normalizeUrl adds https:// to a bare domain and leaves full URLs alone', () => {
  assert.equal(normalizeUrl('example.com'), 'https://example.com');
  assert.equal(normalizeUrl('example.com/path'), 'https://example.com/path');
  assert.equal(normalizeUrl('http://example.com'), 'http://example.com');
  assert.equal(normalizeUrl('https://example.com'), 'https://example.com');
});

// [robustness #5/#6] a site that accepts the connection but never responds must not hang the scan.
test('probe returns (does not hang) against a non-responsive server within the timeout', async () => {
  const hanging = await server(() => { /* never write a response */ });
  const start = Date.now();
  const findings = await probe(hanging.url, { only: ['security'], timeoutMs: 400 });
  const elapsed = Date.now() - start;
  hanging.close();
  assert.ok(elapsed < 8000, `scan should abort quickly, took ${elapsed}ms`);
  assert.ok(findings.find((f) => f.id === 'reachability' && !f.pass), 'reports the site as unreachable');
});
