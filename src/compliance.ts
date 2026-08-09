// src/compliance.ts
// Maps vibetesting-agent findings to recognized standards — OWASP ASVS 4.0.3, OWASP Top 10 (2021), and the
// OWASP Web Security Testing Guide (WSTG) — and reports coverage against the black-box-testable subset of
// ASVS Level 1. This is what lets a scan double as an OWASP conformance check. Refs are keyed by
// finding-id PREFIX (many findings share an id stem, e.g. cookie.<name>, exposed/<path>).

import type { Finding } from './types.js';

export interface StandardRefs { asvs?: string[]; owasp?: string; wstg?: string[]; cwe?: string[]; apiTop10?: string }

// Longest-prefix wins, so specific ids override general stems. cwe = MITRE CWE ids; apiTop10 = OWASP API
// Security Top 10 (2023).
const STANDARDS: Array<[string, StandardRefs]> = [
  ['cookie-prefix.', { asvs: ['V3.4.4'], owasp: 'A05', cwe: ['CWE-614'] }],
  ['cookie.', { asvs: ['V3.4.1', 'V3.4.2', 'V3.4.3'], owasp: 'A05', wstg: ['WSTG-SESS-02'], cwe: ['CWE-614', 'CWE-1004'] }],
  ['cache.sensitive', { asvs: ['V8.2.1'], owasp: 'A05', cwe: ['CWE-525'] }],
  ['error.stacktrace', { asvs: ['V7.4.1'], owasp: 'A05', wstg: ['WSTG-ERRH-01'], cwe: ['CWE-209'] }],
  ['tls.scheme', { asvs: ['V9.1.1'], owasp: 'A02', wstg: ['WSTG-CRYP-03'], cwe: ['CWE-319'] }],
  ['tls.redirect', { asvs: ['V9.1.1'], owasp: 'A02', cwe: ['CWE-319'] }],
  ['tls.cipher', { asvs: ['V9.1.2'], owasp: 'A02', wstg: ['WSTG-CRYP-01'], cwe: ['CWE-327'] }],
  ['tls.protocol', { asvs: ['V9.1.3'], owasp: 'A02', wstg: ['WSTG-CRYP-01'], cwe: ['CWE-326'] }],
  ['tls.hsts-preload', { asvs: ['V14.4.5'], owasp: 'A05', cwe: ['CWE-319'] }],
  ['tls.expiry', { asvs: ['V9.1.1'], owasp: 'A02', cwe: ['CWE-295'] }],
  ['header.strict-transport-security', { asvs: ['V14.4.5'], owasp: 'A05', wstg: ['WSTG-CONF-07'], cwe: ['CWE-319'] }],
  ['header.content-security-policy', { asvs: ['V14.4.3'], owasp: 'A05', wstg: ['WSTG-CONF-12'], cwe: ['CWE-693', 'CWE-79'] }],
  ['header.x-content-type-options', { asvs: ['V14.4.4'], owasp: 'A05', cwe: ['CWE-693'] }],
  ['header.x-frame-options', { asvs: ['V14.4.7'], owasp: 'A05', wstg: ['WSTG-CLNT-09'], cwe: ['CWE-1021'] }],
  ['header.referrer-policy', { asvs: ['V14.4.6'], owasp: 'A05', cwe: ['CWE-200'] }],
  ['header.content-type', { asvs: ['V14.4.1'], owasp: 'A05', cwe: ['CWE-436'] }],
  ['header.permissions-policy', { owasp: 'A05', cwe: ['CWE-693'] }],
  ['header.cross-origin-opener-policy', { owasp: 'A05', cwe: ['CWE-1021'] }],
  ['header.cross-origin-resource-policy', { owasp: 'A05', cwe: ['CWE-1021'] }],
  ['csp.', { asvs: ['V14.4.3'], owasp: 'A05', wstg: ['WSTG-CONF-12'], cwe: ['CWE-79', 'CWE-693'] }],
  ['http.methods', { asvs: ['V14.5.1'], owasp: 'A05', wstg: ['WSTG-CONF-06'], cwe: ['CWE-16'], apiTop10: 'API8:2023' }],
  ['cors.reflection', { asvs: ['V14.5.3'], owasp: 'A05', wstg: ['WSTG-CLNT-07'], cwe: ['CWE-942'], apiTop10: 'API8:2023' }],
  ['open-redirect', { owasp: 'A01', wstg: ['WSTG-CLNT-04'], cwe: ['CWE-601'] }],
  ['sri', { asvs: ['V14.2.3'], owasp: 'A08', wstg: ['WSTG-CLNT-11'], cwe: ['CWE-353', 'CWE-830'] }],
  ['disclosure.', { asvs: ['V14.3.3'], owasp: 'A05', wstg: ['WSTG-INFO-08'], cwe: ['CWE-200'], apiTop10: 'API9:2023' }],
  ['securitytxt', { owasp: 'A05' }],
  ['rate-limit', { owasp: 'A07', wstg: ['WSTG-ATHN-01'], cwe: ['CWE-307', 'CWE-799'], apiTop10: 'API4:2023' }],
  ['components.', { owasp: 'A06', wstg: ['WSTG-CONF-01'], cwe: ['CWE-1104', 'CWE-1035'], apiTop10: 'API8:2023' }],
  ['jwt.alg-none', { asvs: ['V3.5.3'], owasp: 'A02', wstg: ['WSTG-SESS-10'], cwe: ['CWE-347'], apiTop10: 'API2:2023' }],
  ['jwt.', { asvs: ['V3.5.3'], owasp: 'A07', wstg: ['WSTG-SESS-10'], cwe: ['CWE-522', 'CWE-613'], apiTop10: 'API2:2023' }],
  ['host-header.', { owasp: 'A03', wstg: ['WSTG-INPV-17'], cwe: ['CWE-644', 'CWE-20'] }],
  ['csrf', { asvs: ['V4.2.2'], owasp: 'A01', wstg: ['WSTG-SESS-05'], cwe: ['CWE-352'] }],
  ['dom-xss', { asvs: ['V5.3.3'], owasp: 'A03', wstg: ['WSTG-CLNT-01'], cwe: ['CWE-79'] }],
  ['secret.', { asvs: ['V13.1.3'], owasp: 'A02', wstg: ['WSTG-CRYP-04'], cwe: ['CWE-798', 'CWE-312'] }],
  ['sourcemap.exposed', { asvs: ['V14.3.2'], owasp: 'A05', cwe: ['CWE-540'] }],
  ['debug-leak', { asvs: ['V14.3.2'], owasp: 'A05', wstg: ['WSTG-CONF-02'], cwe: ['CWE-200', 'CWE-489'] }],
  ['dir-listing', { asvs: ['V12.5.1'], owasp: 'A05', wstg: ['WSTG-CONF-04'], cwe: ['CWE-548'] }],
  ['robots.sensitive', { owasp: 'A05', wstg: ['WSTG-INFO-01'], cwe: ['CWE-200'] }],
  ['graphql.introspection', { asvs: ['V13.2.1'], owasp: 'A05', cwe: ['CWE-200'], apiTop10: 'API9:2023' }],
  ['exposed', { asvs: ['V12.5.1', 'V14.3.2'], owasp: 'A05', wstg: ['WSTG-CONF-04'], cwe: ['CWE-538', 'CWE-200'] }],
  ['framework', { asvs: ['V14.3.2', 'V14.2.2'], owasp: 'A05', wstg: ['WSTG-CONF-02'], cwe: ['CWE-16'] }],
  ['idor', { owasp: 'A01', wstg: ['WSTG-ATHZ-04'], cwe: ['CWE-639'], apiTop10: 'API1:2023' }],
];

/** Standards mapped to a finding id (longest matching prefix). */
export function refsFor(findingId: string): StandardRefs {
  let best: [string, StandardRefs] | undefined;
  for (const entry of STANDARDS) {
    if (findingId === entry[0] || findingId.startsWith(entry[0])) {
      if (!best || entry[0].length > best[0].length) best = entry;
    }
  }
  return best ? best[1] : {};
}

// The black-box-testable ASVS 4.0.3 Level 1 requirements this scanner targets, each tied to the finding-id
// prefix that verifies it. `covered:false` = a real L1 item we don't yet check (honest gap).
// `cleanSignal`: a passing finding-id that means "this check RAN and found nothing" — needed for checks
// that only emit a finding on failure (else a clean scan would look like the check never ran).
export interface AsvsReq { id: string; text: string; checkPrefix?: string; cleanSignal?: string; covered: boolean }
export const ASVS_L1: AsvsReq[] = [
  { id: 'V3.4.1', text: "Session cookies set 'Secure'", checkPrefix: 'cookie.', covered: true },
  { id: 'V3.4.2', text: "Session cookies set 'HttpOnly'", checkPrefix: 'cookie.', covered: true },
  { id: 'V3.4.3', text: "Session cookies set 'SameSite'", checkPrefix: 'cookie.', covered: true },
  { id: 'V3.4.4', text: "Session cookies use '__Host-' prefix", checkPrefix: 'cookie-prefix.', covered: true },
  { id: 'V3.4.5', text: 'Session cookie Path is scoped tightly', covered: false },
  { id: 'V7.4.1', text: 'Generic error messages, no stack traces', checkPrefix: 'error.stacktrace', cleanSignal: 'exposure.none', covered: true },
  { id: 'V8.2.1', text: 'Anti-caching headers on sensitive responses', checkPrefix: 'cache.sensitive', covered: true },
  { id: 'V9.1.1', text: 'TLS on all connections, no insecure fallback', checkPrefix: 'tls.scheme', covered: true },
  { id: 'V9.1.2', text: 'Only strong cipher suites', checkPrefix: 'tls.cipher', covered: true },
  { id: 'V9.1.3', text: 'Only latest TLS versions (1.2/1.3)', checkPrefix: 'tls.protocol', covered: true },
  { id: 'V12.5.1', text: 'Backup/temp/archive files not served', checkPrefix: 'exposed', cleanSignal: 'exposure.none', covered: true },
  { id: 'V13.1.3', text: 'URLs do not expose keys/tokens', checkPrefix: 'secret.', covered: true },
  { id: 'V14.2.2', text: 'Sample apps/docs/default configs removed', checkPrefix: 'framework', covered: true },
  { id: 'V14.2.3', text: 'External assets use Subresource Integrity', checkPrefix: 'sri', covered: true },
  { id: 'V14.3.2', text: 'Debug modes disabled in production', checkPrefix: 'debug-leak', cleanSignal: 'exposure.none', covered: true },
  { id: 'V14.3.3', text: 'No version info in headers/responses', checkPrefix: 'disclosure.', covered: true },
  { id: 'V14.4.1', text: 'Content-Type + safe charset on responses', checkPrefix: 'header.content-type', covered: true },
  { id: 'V14.4.2', text: 'Content-Disposition on API responses', covered: false },
  { id: 'V14.4.3', text: 'Content-Security-Policy present', checkPrefix: 'header.content-security-policy', covered: true },
  { id: 'V14.4.4', text: 'X-Content-Type-Options: nosniff', checkPrefix: 'header.x-content-type-options', covered: true },
  { id: 'V14.4.5', text: 'Strict-Transport-Security on all responses', checkPrefix: 'header.strict-transport-security', covered: true },
  { id: 'V14.4.6', text: 'Referrer-Policy header set', checkPrefix: 'header.referrer-policy', covered: true },
  { id: 'V14.4.7', text: 'Clickjacking defense (frame-ancestors/XFO)', checkPrefix: 'header.x-frame-options', covered: true },
  { id: 'V14.5.1', text: 'Only in-use HTTP methods accepted', checkPrefix: 'http.methods', covered: true },
  { id: 'V14.5.3', text: 'CORS uses a strict allow-list (no null)', checkPrefix: 'cors.reflection', covered: true },
];

export type AsvsStatus = 'pass' | 'fail' | 'not-observed' | 'not-covered';
export interface AsvsResult extends AsvsReq { status: AsvsStatus }

/** Grade each ASVS L1 requirement from a scan's findings. */
export function asvsCoverage(findings: Finding[]): AsvsResult[] {
  return ASVS_L1.map((req) => {
    if (!req.covered || !req.checkPrefix) return { ...req, status: 'not-covered' as AsvsStatus };
    const related = findings.filter((f) => f.id === req.checkPrefix || f.id.startsWith(req.checkPrefix!));
    let status: AsvsStatus;
    if (related.some((f) => !f.pass)) status = 'fail';
    else if (related.length) status = 'pass';
    // No matching finding: if the check only fails loudly, a passing cleanSignal means it ran clean.
    else if (req.cleanSignal && findings.some((f) => f.id === req.cleanSignal && f.pass)) status = 'pass';
    else status = 'not-observed';
    return { ...req, status };
  });
}

/** Which OWASP Top 10 categories the scan touched (from failing findings). */
export function owaspTop10Hit(findings: Finding[]): Record<string, number> {
  const hits: Record<string, number> = {};
  for (const f of findings) {
    if (f.pass) continue;
    const o = refsFor(f.id).owasp;
    if (o) hits[o] = (hits[o] || 0) + 1;
  }
  return hits;
}

export const OWASP_TOP10_NAMES: Record<string, string> = {
  A01: 'Broken Access Control', A02: 'Cryptographic Failures', A03: 'Injection',
  A04: 'Insecure Design', A05: 'Security Misconfiguration', A06: 'Vulnerable Components',
  A07: 'Auth Failures', A08: 'Software/Data Integrity', A09: 'Logging/Monitoring', A10: 'SSRF',
};

export const OWASP_API_TOP10_NAMES: Record<string, string> = {
  'API1:2023': 'Broken Object Level Authorization (BOLA)',
  'API3:2023': 'Broken Object Property Level Authorization',
  'API4:2023': 'Unrestricted Resource Consumption',
  'API5:2023': 'Broken Function Level Authorization',
  'API8:2023': 'Security Misconfiguration',
  'API9:2023': 'Improper Inventory Management',
};

/** OWASP API Security Top 10 (2023) categories hit by failing findings. */
export function apiTop10Hit(findings: Finding[]): Record<string, number> {
  const hits: Record<string, number> = {};
  for (const f of findings) {
    if (f.pass) continue;
    const a = refsFor(f.id).apiTop10;
    if (a) hits[a] = (hits[a] || 0) + 1;
  }
  return hits;
}

/** Distinct CWE ids across failing findings. */
export function cwesHit(findings: Finding[]): string[] {
  const set = new Set<string>();
  for (const f of findings) { if (!f.pass) for (const c of refsFor(f.id).cwe ?? []) set.add(c); }
  return [...set].sort();
}

/** Mozilla-Observatory-style A+–F grade from failing security/exposure/secrets findings. */
export function securityGrade(findings: Finding[]): { grade: string; score: number } {
  const weight: Record<string, number> = { high: 20, medium: 8, low: 3, info: 0 };
  let score = 100;
  for (const f of findings) {
    if (f.pass || !['security', 'exposure', 'secrets'].includes(f.category)) continue;
    score -= weight[f.severity] ?? 0;
  }
  score = Math.max(0, score);
  const grade = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 75 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F';
  return { grade, score };
}

/** SSL-Labs-style A+–F TLS grade from the tls.* findings. */
export function tlsGrade(findings: Finding[]): string {
  const fail = (id: string) => findings.some((f) => f.id === id && !f.pass);
  const pass = (id: string) => findings.some((f) => f.id === id && f.pass);
  if (fail('tls.scheme')) return 'F';                       // not served over HTTPS
  if (fail('tls.protocol') || fail('tls.cipher')) return 'C'; // deprecated protocol / weak cipher
  if (fail('tls.redirect')) return 'B';                     // no HTTP→HTTPS redirect
  if (pass('tls.hsts-preload')) return 'A+';                // modern + preload-eligible HSTS
  return pass('tls.protocol') ? 'A' : 'B';
}
