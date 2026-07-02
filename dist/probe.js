// src/probe.ts
// Orchestrates the full black-box scan: fetch the homepage ONCE, then run every enabled category
// against that shared context. `probe()` runs all categories by default (it used to be security-only);
// pass `only`/`skip` to scope it. The result is a flat Finding[] the CLI groups + gates on.
import { securityChecks, secretChecks, exposureChecks, reliabilityChecks, seoChecks, a11yChecks, performanceChecks, } from './checks.js';
import { dnsChecks } from './dns.js';
import { agentChecks } from './agent.js';
const RUNNERS = {
    security: securityChecks,
    secrets: secretChecks,
    exposure: exposureChecks,
    dns: dnsChecks,
    reliability: reliabilityChecks,
    seo: seoChecks,
    a11y: a11yChecks,
    performance: performanceChecks,
    agent: agentChecks,
};
export const ALL_CATEGORIES = Object.keys(RUNNERS);
/** Add https:// when the user typed a bare domain, so `anal-probe example.com` just works. */
export function normalizeUrl(input) {
    return /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
}
async function buildContext(baseUrl, opts) {
    const url = new URL(baseUrl);
    let res = null;
    let html = '';
    let headers = new Headers();
    // The homepage fetch is the one call not going through safeFetch, so it needs its own hard timeout —
    // otherwise a site that accepts the connection but never responds would hang the entire scan.
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), opts.timeoutMs ?? 10_000);
    try {
        res = await fetch(url.origin, { redirect: 'follow', signal: ac.signal });
        headers = res.headers;
        if ((res.headers.get('content-type') || '').includes('html')) {
            html = (await res.text()).slice(0, 5_000_000);
        }
    }
    catch {
        res = null;
    }
    finally {
        clearTimeout(timer);
    }
    return { baseUrl, origin: url.origin, url, res, html, headers, opts };
}
/** Run the comprehensive scan. Returns every finding across the selected categories. */
export async function probe(baseUrl, opts = {}) {
    const ctx = await buildContext(baseUrl, opts);
    const selected = (opts.only ?? ALL_CATEGORIES).filter((c) => !(opts.skip ?? []).includes(c));
    const results = await Promise.all(selected.map((c) => RUNNERS[c](ctx).catch((e) => [
        { category: c, id: `${c}.error`, title: `${c} check crashed`, severity: 'info', pass: true, detail: String(e?.message || e) },
    ])));
    return results.flat();
}
/** Alias — reads better for the full-app use case. */
export const scan = probe;
export function summarize(findings) {
    let passed = 0, failed = 0, failHigh = 0, failMedium = 0, failLow = 0;
    const byCategory = {};
    for (const f of findings) {
        (byCategory[f.category] ??= { passed: 0, failed: 0 });
        if (f.pass) {
            passed++;
            byCategory[f.category].passed++;
            continue;
        }
        failed++;
        byCategory[f.category].failed++;
        if (f.severity === 'high')
            failHigh++;
        else if (f.severity === 'medium')
            failMedium++;
        else if (f.severity === 'low')
            failLow++;
    }
    return { passed, failed, failHigh, failMedium, failLow, byCategory };
}
