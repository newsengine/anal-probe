/**
 * MITRE ATLAS AI/LLM-attack checks. Proves AI-surface detection gates the checks, the model-artifact /
 * inference / cost-DoS / prompt-injection checks fire on a vulnerable AI app, and nothing runs on a
 * non-AI app. Imports dist/ so we test the shipped build.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { probe } from '../dist/probe.js';
import { detectAiSurface, atlasCheckSpecs } from '../dist/atlas.js';
import { catalogEntryFor } from '../dist/catalog.js';
import { startServer } from './helpers/http-fixture.ts';
import type { ScanContext, Finding } from '../dist/types.js';

const anyFail = (fs: Finding[], prefix: string) => fs.some((f) => !f.pass && f.id.startsWith(prefix));

// A deliberately-vulnerable AI app: chat endpoint (unthrottled, prompt-injectable) + downloadable model.
function aiHandler(): http.RequestListener {
  return (req, res) => {
    const url = new URL(req.url || '/', 'http://fixture.local');
    const p = url.pathname;
    if (p === '/model.gguf') { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('GGUF\x00\x00 fake weights'); return; }
    if (p === '/api/chat') {
      if (req.method === 'POST') {
        let body = ''; req.on('data', (c) => (body += c)); req.on('end', () => {
          // Naively obeys injected instructions → echoes the canary back (prompt injection).
          const m = body.match(/token and nothing else:\s*(\S+)/);
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ reply: m ? m[1] : 'hello' }));
        });
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ ok: true })); return; // unthrottled
    }
    if (p === '/') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<!DOCTYPE html><html><head><title>AI App</title></head><body>
        <h1>Ask AI anything</h1><p>Our chatbot is powered by GPT-4.</p>
        <script>fetch('/api/chat')</script></body></html>`);
      return;
    }
    res.writeHead(404); res.end('nope');
  };
}

test('atlas: detectAiSurface distinguishes AI from non-AI pages', () => {
  const ai = { baseUrl: 'https://x.test', origin: 'https://x.test', url: new URL('https://x.test'),
    html: `<h1>Ask AI</h1><p>powered by claude-3</p><script>fetch('/api/chat')</script>` } as ScanContext;
  const s = detectAiSurface(ai);
  assert.equal(s.present, true);
  assert.ok(s.endpoints.includes('/api/chat'));

  const plain = { baseUrl: 'https://x.test', origin: 'https://x.test', url: new URL('https://x.test'),
    html: `<h1>Welcome</h1><p>a normal marketing page</p>` } as ScanContext;
  assert.equal(detectAiSurface(plain).present, false);
});

test('atlas: model-artifact + inference checks fire on a vulnerable AI app', async () => {
  const srv = await startServer(aiHandler());
  try {
    const findings = await probe(srv.url, { only: ['atlas'], timeoutMs: 8000 });
    assert.ok(findings.some((f) => f.id === 'atlas.detected'), 'AI surface should be detected');
    assert.ok(anyFail(findings, 'atlas.model-artifact'), 'downloadable model.gguf should fail (AML.T0044)');
    assert.ok(findings.some((f) => f.id === 'atlas.inference-open'), 'reachable inference endpoint noted (AML.T0040)');
    // Opt-in probes are OFF by default.
    assert.ok(!anyFail(findings, 'atlas.cost-dos'), 'cost-dos must be opt-in');
    assert.ok(!anyFail(findings, 'atlas.prompt-injection'), 'prompt-injection must be opt-in');
  } finally { await srv.close(); }
});

test('atlas: opt-in cost-DoS + prompt-injection fire when enabled', async () => {
  const srv = await startServer(aiHandler());
  try {
    const findings = await probe(srv.url, { only: ['atlas'], rateLimitScan: true, aiProbe: true, timeoutMs: 8000 });
    assert.ok(anyFail(findings, 'atlas.cost-dos'), 'unthrottled AI endpoint should fail cost-DoS (AML.T0034/T0029)');
    assert.ok(anyFail(findings, 'atlas.prompt-injection'), 'canary echo should fail prompt-injection (AML.T0051)');
    const pi = findings.find((f) => f.id.startsWith('atlas.prompt-injection'))!;
    assert.match(pi.detail, /AML\.T0051/);
  } finally { await srv.close(); }
});

test('atlas: non-AI app yields a clean atlas.none and no AI checks', async () => {
  const srv = await startServer(((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<h1>Just a shop</h1><p>buy things</p>'); }) as http.RequestListener);
  try {
    const findings = await probe(srv.url, { only: ['atlas'], rateLimitScan: true, aiProbe: true, timeoutMs: 8000 });
    assert.ok(findings.some((f) => f.id === 'atlas.none'), 'expected atlas.none on a non-AI page');
    assert.ok(!findings.some((f) => f.id !== 'atlas.none' && f.id.startsWith('atlas.')), 'no ATLAS checks should run');
  } finally { await srv.close(); }
});

test('atlas: every ATLAS check spec is catalogued', () => {
  for (const s of atlasCheckSpecs()) assert.ok(catalogEntryFor(s.id), `ATLAS check ${s.id} is not catalogued`);
});
