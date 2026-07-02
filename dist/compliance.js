// src/compliance.ts
// Maps anal-probe findings to recognized standards — OWASP ASVS 4.0.3, OWASP Top 10 (2021), and the
// OWASP Web Security Testing Guide (WSTG) — and reports coverage against the black-box-testable subset of
// ASVS Level 1. This is what lets a scan double as an OWASP conformance check. Refs are keyed by
// finding-id PREFIX (many findings share an id stem, e.g. cookie.<name>, exposed/<path>).
// Longest-prefix wins, so specific ids override general stems.
const STANDARDS = [
    ['cookie-prefix.', { asvs: ['V3.4.4'], owasp: 'A05' }],
    ['cookie.', { asvs: ['V3.4.1', 'V3.4.2', 'V3.4.3'], owasp: 'A05', wstg: ['WSTG-SESS-02'] }],
    ['cache.sensitive', { asvs: ['V8.2.1'], owasp: 'A05' }],
    ['error.stacktrace', { asvs: ['V7.4.1'], owasp: 'A05', wstg: ['WSTG-ERRH-01'] }],
    ['tls.scheme', { asvs: ['V9.1.1'], owasp: 'A02', wstg: ['WSTG-CRYP-03'] }],
    ['tls.redirect', { asvs: ['V9.1.1'], owasp: 'A02' }],
    ['tls.cipher', { asvs: ['V9.1.2'], owasp: 'A02', wstg: ['WSTG-CRYP-01'] }],
    ['tls.protocol', { asvs: ['V9.1.3'], owasp: 'A02', wstg: ['WSTG-CRYP-01'] }],
    ['tls.hsts-preload', { asvs: ['V14.4.5'], owasp: 'A05' }],
    ['tls.expiry', { asvs: ['V9.1.1'], owasp: 'A02' }],
    ['header.strict-transport-security', { asvs: ['V14.4.5'], owasp: 'A05', wstg: ['WSTG-CONF-07'] }],
    ['header.content-security-policy', { asvs: ['V14.4.3'], owasp: 'A05', wstg: ['WSTG-CONF-12'] }],
    ['header.x-content-type-options', { asvs: ['V14.4.4'], owasp: 'A05' }],
    ['header.x-frame-options', { asvs: ['V14.4.7'], owasp: 'A05', wstg: ['WSTG-CLNT-09'] }],
    ['header.referrer-policy', { asvs: ['V14.4.6'], owasp: 'A05' }],
    ['header.content-type', { asvs: ['V14.4.1'], owasp: 'A05' }],
    ['header.permissions-policy', { owasp: 'A05' }],
    ['header.cross-origin-opener-policy', { owasp: 'A05' }],
    ['header.cross-origin-resource-policy', { owasp: 'A05' }],
    ['csp.', { asvs: ['V14.4.3'], owasp: 'A05', wstg: ['WSTG-CONF-12'] }],
    ['http.methods', { asvs: ['V14.5.1'], owasp: 'A05', wstg: ['WSTG-CONF-06'] }],
    ['cors.reflection', { asvs: ['V14.5.3'], owasp: 'A05', wstg: ['WSTG-CLNT-07'] }],
    ['open-redirect', { owasp: 'A01', wstg: ['WSTG-CLNT-04'] }],
    ['sri', { asvs: ['V14.2.3'], owasp: 'A08', wstg: ['WSTG-CLNT-11'] }],
    ['disclosure.', { asvs: ['V14.3.3'], owasp: 'A05', wstg: ['WSTG-INFO-08'] }],
    ['securitytxt', { owasp: 'A05' }],
    ['rate-limit', { owasp: 'A07', wstg: ['WSTG-ATHN-01'] }],
    ['secret.', { asvs: ['V13.1.3'], owasp: 'A02', wstg: ['WSTG-CRYP-04'] }],
    ['sourcemap.exposed', { asvs: ['V14.3.2'], owasp: 'A05' }],
    ['debug-leak', { asvs: ['V14.3.2'], owasp: 'A05', wstg: ['WSTG-CONF-02'] }],
    ['dir-listing', { asvs: ['V12.5.1'], owasp: 'A05', wstg: ['WSTG-CONF-04'] }],
    ['robots.sensitive', { owasp: 'A05', wstg: ['WSTG-INFO-01'] }],
    ['graphql.introspection', { asvs: ['V13.2.1'], owasp: 'A05' }],
    ['exposed', { asvs: ['V12.5.1', 'V14.3.2'], owasp: 'A05', wstg: ['WSTG-CONF-04'] }],
    ['framework', { asvs: ['V14.3.2', 'V14.2.2'], owasp: 'A05', wstg: ['WSTG-CONF-02'] }],
    ['idor', { owasp: 'A01', wstg: ['WSTG-ATHZ-04'] }],
];
/** Standards mapped to a finding id (longest matching prefix). */
export function refsFor(findingId) {
    let best;
    for (const entry of STANDARDS) {
        if (findingId === entry[0] || findingId.startsWith(entry[0])) {
            if (!best || entry[0].length > best[0].length)
                best = entry;
        }
    }
    return best ? best[1] : {};
}
export const ASVS_L1 = [
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
/** Grade each ASVS L1 requirement from a scan's findings. */
export function asvsCoverage(findings) {
    return ASVS_L1.map((req) => {
        if (!req.covered || !req.checkPrefix)
            return { ...req, status: 'not-covered' };
        const related = findings.filter((f) => f.id === req.checkPrefix || f.id.startsWith(req.checkPrefix));
        let status;
        if (related.some((f) => !f.pass))
            status = 'fail';
        else if (related.length)
            status = 'pass';
        // No matching finding: if the check only fails loudly, a passing cleanSignal means it ran clean.
        else if (req.cleanSignal && findings.some((f) => f.id === req.cleanSignal && f.pass))
            status = 'pass';
        else
            status = 'not-observed';
        return { ...req, status };
    });
}
/** Which OWASP Top 10 categories the scan touched (from failing findings). */
export function owaspTop10Hit(findings) {
    const hits = {};
    for (const f of findings) {
        if (f.pass)
            continue;
        const o = refsFor(f.id).owasp;
        if (o)
            hits[o] = (hits[o] || 0) + 1;
    }
    return hits;
}
export const OWASP_TOP10_NAMES = {
    A01: 'Broken Access Control', A02: 'Cryptographic Failures', A03: 'Injection',
    A04: 'Insecure Design', A05: 'Security Misconfiguration', A06: 'Vulnerable Components',
    A07: 'Auth Failures', A08: 'Software/Data Integrity', A09: 'Logging/Monitoring', A10: 'SSRF',
};
