import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderAgentReport, renderFindingPrompt } from '../dist/agent-report.js';
import { renderGherkinFeature } from '../dist/gherkin.js';
import type { Finding } from '../dist/types.js';

const findings: Finding[] = [
  {
    id: 'header.content-security-policy',
    category: 'security',
    title: 'Missing CSP',
    severity: 'high',
    pass: false,
    detail: 'No Content-Security-Policy header',
    fix: 'Add a CSP with nonces',
  },
  {
    id: 'dns.caa',
    category: 'dns',
    title: 'No CAA record',
    severity: 'low',
    pass: false,
    detail: 'CAA missing',
    fix: 'Add CAA at DNS',
  },
  {
    id: 'tls.scheme',
    category: 'security',
    title: 'HTTPS ok',
    severity: 'info',
    pass: true,
    detail: 'uses https',
  },
];

test('agent report ranks failures as P1/P2 with fix+verify', () => {
  const md = renderAgentReport(findings, { url: 'https://example.com', projectName: 'Demo' });
  assert.match(md, /Demo — security/);
  assert.match(md, /## P1 — Missing CSP/);
  assert.match(md, /## P2 — No CAA/);
  assert.match(md, /\*\*Fix:\*\*/);
  assert.match(md, /\*\*Verify \(accept\):\*\*/);
  assert.match(md, /header\.content-security-policy/);
  assert.match(md, /Passing checks/);
  assert.doesNotMatch(md, /## P3/); // only 2 fails
});

test('finding prompt is agent-pasteable', () => {
  const p = renderFindingPrompt('https://example.com', findings[0]);
  assert.match(p, /Fix this vibetesting-agent finding/);
  assert.match(p, /Missing CSP/);
});

test('gherkin emits scenarios per failing finding + gate', () => {
  const feature = renderGherkinFeature(findings, { url: 'https://example.com', projectName: 'Demo' });
  assert.match(feature, /Feature: Demo security hygiene/);
  assert.match(feature, /@security @sev-high @cat-security/);
  assert.match(feature, /Scenario: Missing CSP/);
  assert.match(feature, /finding "header\.content-security-policy"/);
  assert.match(feature, /No new high-severity regressions/);
});
