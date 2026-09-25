/**
 * #42 — authenticated deep-crawl + coverage map. Proves the BFS discovers linked pages, query params,
 * forms (action/method/fields) and /api routes, stays same-origin, respects caps, and sends auth headers.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { buildCoverageMap, parseForms, summarizeCoverage } from '../dist/crawl-map.js';
import { startServer } from './helpers/http-fixture.ts';

function siteHandler(seenAuth: { hit: boolean }): http.RequestListener {
  return (req, res) => {
    if (req.headers.cookie) seenAuth.hit = true;
    const url = new URL(req.url || '/', 'http://fixture.local');
    const p = url.pathname;
    const html = (b: string) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(b); };
    if (p === '/') return html(`<a href="/about">About</a> <a href="/search?q=hi">Search</a>
      <a href="https://evil.example/x">offsite</a>
      <form action="/login" method="post"><input name="email"><input name="password"></form>
      <script>fetch('/api/data')</script>`);
    if (p === '/about') return html(`<a href="/">home</a> <a href="/deep?ref=1">deep</a>`);
    if (p === '/search') return html(`<p>results</p>`);
    if (p === '/deep') return html(`<p>deep page</p>`);
    if (p === '/api/data') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); return; }
    res.writeHead(404); res.end('nf');
  };
}

test('crawl-map: parseForms extracts action/method/fields', () => {
  const forms = parseForms('https://x.test/', `<form action="/login" method="POST"><input name="email"><textarea name="bio"></textarea></form>`);
  assert.equal(forms.length, 1);
  assert.equal(forms[0].method, 'post');
  assert.ok(forms[0].action.endsWith('/login'));
  assert.deepEqual(forms[0].fields.sort(), ['bio', 'email']);
});

test('crawl-map: BFS discovers endpoints, params, forms, apis; stays same-origin', async () => {
  const seenAuth = { hit: false };
  const srv = await startServer(siteHandler(seenAuth));
  try {
    const map = await buildCoverageMap(srv.url, { extraHeaders: { cookie: 'sid=abc' }, maxPages: 20, timeoutMs: 8000 });
    assert.ok(map.endpoints.includes('/about'), `missing /about in ${map.endpoints.join(',')}`);
    assert.ok(map.endpoints.includes('/search'));
    assert.ok(map.endpoints.includes('/deep'), 'depth-2 page reached');
    assert.ok(map.params.includes('q') && map.params.includes('ref'), `params: ${map.params.join(',')}`);
    assert.ok(map.apis.includes('/api/data'), `apis: ${map.apis.join(',')}`);
    const login = map.forms.find((f) => f.action.endsWith('/login'));
    assert.ok(login && login.method === 'post' && login.fields.includes('password'), 'login form captured');
    assert.ok(!map.endpoints.some((e) => e.includes('evil')), 'never leaves origin');
    assert.ok(seenAuth.hit, 'auth header was sent on same-origin requests');
    assert.match(summarizeCoverage(map), /coverage: \d+ page/);
  } finally { await srv.close(); }
});

test('crawl-map: respects the page cap', async () => {
  const srv = await startServer(siteHandler({ hit: false }));
  try {
    const map = await buildCoverageMap(srv.url, { maxPages: 1, timeoutMs: 8000 });
    assert.equal(map.pagesVisited, 1);
    assert.ok(map.capped, 'should report capped when more pages remained');
  } finally { await srv.close(); }
});
