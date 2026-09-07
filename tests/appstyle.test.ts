/**
 * App-style (business-archetype) detection + type-specific rule packs. Proves the detector classifies
 * the top archetypes correctly, that a type's rules run only on a confident match, and that every rule
 * is catalogued.
 *
 * Imports dist/ so we test the shipped build.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { probe } from '../dist/probe.js';
import { detectAppStyles, appStyleRuleSpecs, looksLikeArticlePath } from '../dist/appstyle.js';
import { catalogEntryFor } from '../dist/catalog.js';
import { startServer } from './helpers/http-fixture.ts';
import type { ScanContext } from '../dist/types.js';

// Minimal ScanContext for pure detector unit tests (detectAppStyles reads html + url only).
function ctxOf(html: string, path = '/'): ScanContext {
  return {
    baseUrl: `https://x.test${path}`,
    origin: 'https://x.test',
    url: new URL(`https://x.test${path}`),
    res: new Response(html),
    html,
    headers: new Headers({ 'content-type': 'text/html' }),
    opts: {},
  } as ScanContext;
}

const top = (html: string, path?: string) => detectAppStyles(ctxOf(html, path))[0]?.key;

test('appstyle: detector classifies the major archetypes', () => {
  assert.equal(top(`<script type="application/ld+json">{"@type":"Product","offers":{"@type":"Offer"}}</script><button>Add to cart</button><div>checkout</div>`), 'ecommerce');
  assert.equal(top(`<form><input type="password"></form><a>Forgot password</a> single sign-on`, '/login'), 'auth-portal');
  assert.equal(top(`<script type="application/ld+json">{"@type":"BlogPosting"}</script><link type="application/rss+xml"><div>posted on ... read more</div>`, '/blog/post'), 'blog-cms');
  assert.equal(top(`<h1>Your account balance</h1><p>transfer, deposit and withdraw funds</p> KYC required`), 'fintech');
  assert.equal(top(`<script type="application/ld+json">{"@type":"JobPosting"}</script><a>Apply now</a> careers`, '/jobs'), 'job-board');
});

test('appstyle: nondescript page is not force-classified', () => {
  const styles = detectAppStyles(ctxOf('<h1>Hello world</h1><p>welcome to my page</p>'));
  const strong = styles.filter((s) => s.score >= 3);
  assert.equal(strong.length, 0, `expected no confident archetype, got: ${strong.map((s) => s.key).join(', ')}`);
});

test('appstyle: ecommerce rules fire end-to-end on a store with weak headers', async () => {
  const html = `<!DOCTYPE html><html><head><title>Shop</title>
    <script type="application/ld+json">{"@type":"Product","name":"Thing","offers":{"@type":"Offer","price":"9.99"}}</script>
    </head><body><h1>Buy Thing</h1><button>Add to cart</button><a href="/checkout">Checkout</a>
    <script src="https://cdn.example.com/tracker.js"></script></body></html>`;
  const srv = await startServer(((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' }); // deliberately no CSP / no HSTS
    res.end(html);
  }) as http.RequestListener);
  try {
    const findings = await probe(srv.url, { only: ['appstyle'], timeoutMs: 8000 });
    const detected = findings.find((f) => f.id === 'appstyle.detected');
    assert.ok(detected && /ecommerce|E-commerce/i.test(detected.detail), `expected ecommerce detection, got: ${detected?.detail}`);
    assert.ok(findings.some((f) => f.id === 'appstyle.ecommerce.csp' && !f.pass), 'expected missing-CSP fail on a store');
    assert.ok(findings.some((f) => f.id === 'appstyle.ecommerce.third-party-scripts' && !f.pass), 'expected un-pinned third-party script fail');
  } finally {
    await srv.close();
  }
});

test('appstyle: no false archetype rules on a plain hardened page', async () => {
  const html = `<!DOCTYPE html><html lang="en"><head><title>Just a page</title></head><body><h1>Hello</h1><p>nothing to see</p></body></html>`;
  const srv = await startServer(((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html);
  }) as http.RequestListener);
  try {
    const findings = await probe(srv.url, { only: ['appstyle'], timeoutMs: 8000 });
    assert.ok(findings.some((f) => f.id === 'appstyle.none'), 'expected appstyle.none on a nondescript page');
    assert.ok(!findings.some((f) => f.id.startsWith('appstyle.') && f.id !== 'appstyle.none' && f.id !== 'appstyle.detected'), 'no type-specific rules should run');
  } finally {
    await srv.close();
  }
});

test('appstyle: every rule spec is catalogued and covers all 20 app types', () => {
  const specs = appStyleRuleSpecs();
  for (const s of specs) {
    assert.ok(catalogEntryFor(s.id), `app-style rule ${s.id} is not catalogued`);
  }
  const keys = new Set(specs.map((s) => s.key));
  assert.equal(keys.size, 20, `expected rules for 20 app types, got ${keys.size}: ${[...keys].join(', ')}`);
});

// ── Regression: article-schema false positive (2026-09-08) ──────────────────
// appstyle rules analyse the HOMEPAGE. A homepage legitimately carries
// WebSite/Organization schema and no Article schema, so the blog article-schema
// rule failed on every correctly built news site — including dynamicbusiness.com,
// whose article pages emit full NewsArticle JSON-LD (verified with this very
// extraction). A check that cries wolf gets ignored, so it now only judges
// pages that actually look like articles.
test('looksLikeArticlePath: listings and homepages are not articles', () => {
  for (const p of ['/', '/blog', '/news', '/articles', '/category/finance', '/tag/ai', '/topics/news', '/author/jane', '/page/2']) {
    assert.equal(looksLikeArticlePath(p), false, `${p} should not count as an article`);
  }
});

test('looksLikeArticlePath: real article URLs are articles', () => {
  for (const p of [
    '/article/turns-out-the-scariest-sales-tactic-is-also-the-most-effective-one',
    '/retail-blogs/why-more-australian-retailers-are-rethinking-their-supplier-contracts',
    '/topics/news/australian-ai-funding-hits-839m.html',
    '/blog/hello-world',
  ]) {
    assert.equal(looksLikeArticlePath(p), true, `${p} should count as an article`);
  }
});
