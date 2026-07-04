// src/components.ts
// OWASP A06:2021 — Vulnerable & Outdated Components, for CLIENT-SIDE JavaScript libraries (a retire.js-style
// pass). Every real security review checks whether the page ships a jQuery/Angular/Bootstrap/Lodash/etc with a
// known CVE; anal-probe's `cve` mode covers the SERVER stack via NVD, but nothing looked at the JS the browser
// actually loads. This detects library + version from script/link URLs and inline banners (no code execution),
// then matches a curated table of known-vulnerable version ranges. Black-box, zero-dependency.
import { html as H, resolveUrl } from './core.js';
const f = (id, title, severity, pass, detail, fix) => ({ category: 'components', id, title, severity, pass, detail, fix });
// --- semver-lite: compare dotted numeric versions, tolerating pre-release/junk suffixes. ---
export function parseVersion(v) {
    return String(v).split(/[.+-]/).slice(0, 3).map((p) => parseInt(p, 10) || 0);
}
export function versionLt(a, b) {
    const x = parseVersion(a), y = parseVersion(b);
    for (let i = 0; i < 3; i++) {
        if ((x[i] || 0) < (y[i] || 0))
            return true;
        if ((x[i] || 0) > (y[i] || 0))
            return false;
    }
    return false;
}
const DETECTORS = [
    // Order matters: match the more specific name (jquery-ui, jquery.mobile) before bare jquery.
    { key: 'jquery-ui', url: /jquery[.-]ui[.@/-](\d+\.\d+\.\d+)/i, banner: /jQuery UI[ -]v?(\d+\.\d+\.\d+)/i },
    { key: 'jquery', url: /(?:libs\/jquery\/|jquery@|jquery[.-])(\d+\.\d+\.\d+)/i, banner: /jQuery v(\d+\.\d+\.\d+)/i },
    { key: 'angular', url: /(?:libs\/angular(?:js)?\/|angular(?:js)?@|angular[.-])(\d+\.\d+\.\d+)/i, banner: /AngularJS v(\d+\.\d+\.\d+)/i },
    { key: 'bootstrap', url: /(?:libs\/(?:twitter-)?bootstrap\/|bootstrap@|bootstrap[.-])(\d+\.\d+\.\d+)/i, banner: /Bootstrap v(\d+\.\d+\.\d+)/i },
    { key: 'lodash', url: /(?:libs\/lodash\.js\/|lodash@|lodash[.-])(\d+\.\d+\.\d+)/i, banner: /lodash (?:lodash )?v?(\d+\.\d+\.\d+)/i },
    { key: 'underscore', url: /(?:libs\/underscore\.js\/|underscore@|underscore[.-])(\d+\.\d+\.\d+)/i, banner: /Underscore\.js (\d+\.\d+\.\d+)/i },
    { key: 'moment', url: /(?:libs\/moment\.js\/|moment@|moment[.-])(\d+\.\d+\.\d+)/i, banner: /moment(?:\.js)? version (\d+\.\d+\.\d+)/i },
    { key: 'handlebars', url: /(?:libs\/handlebars\.js\/|handlebars@|handlebars[.-])(\d+\.\d+\.\d+)/i, banner: /Handlebars v(\d+\.\d+\.\d+)/i },
    { key: 'axios', url: /(?:axios@|axios[.-])(\d+\.\d+\.\d+)/i, banner: /axios v(\d+\.\d+\.\d+)/i },
    { key: 'dompurify', url: /(?:dompurify@|(?:purify|dompurify)[.-])(\d+\.\d+\.\d+)/i, banner: /DOMPurify (\d+\.\d+\.\d+)/i },
    { key: 'vue', url: /(?:libs\/vue\/|vue@|vue[.-])(\d+\.\d+\.\d+)/i, banner: /Vue\.js v(\d+\.\d+\.\d+)/i },
    { key: 'select2', url: /(?:libs\/select2\/|select2@|select2[.-])(\d+\.\d+\.\d+)/i, banner: /Select2 (\d+\.\d+\.\d+)/i },
];
export const VULN_DB = {
    jquery: [
        { below: '3.5.0', severity: 'medium', ref: 'CVE-2020-11022/11023', note: 'XSS via jQuery.htmlPrefilter when passing untrusted HTML to DOM-manipulation methods' },
        { below: '1.9.0', severity: 'medium', ref: 'CVE-2012-6708', note: 'selector-based XSS in very old jQuery' },
    ],
    'jquery-ui': [{ below: '1.13.2', severity: 'medium', ref: 'CVE-2022-31160', note: 'XSS in the checkboxradio widget when refreshing with untrusted labels' }],
    angular: [{ below: '1.8.3', severity: 'high', ref: 'AngularJS EOL + multiple XSS/sandbox-escape CVEs', note: 'AngularJS 1.x is end-of-life (no security fixes); multiple known XSS/CSP-bypass issues' }],
    bootstrap: [
        { below: '3.4.1', severity: 'medium', ref: 'CVE-2019-8331', note: 'XSS in data-template / tooltip/popover (Bootstrap 3.x)' },
        { below: '4.3.1', severity: 'medium', ref: 'CVE-2019-8331', note: 'XSS in data-template (Bootstrap 4.x < 4.3.1)' },
    ],
    lodash: [{ below: '4.17.21', severity: 'high', ref: 'CVE-2021-23337 / CVE-2020-8203', note: 'command injection via _.template and prototype pollution' }],
    underscore: [{ below: '1.13.0', severity: 'high', ref: 'CVE-2021-23358', note: 'arbitrary code execution via the template function' }],
    moment: [{ below: '2.29.4', severity: 'medium', ref: 'CVE-2022-31129', note: 'ReDoS parsing very long date strings (also: Moment is in maintenance mode)' }],
    handlebars: [{ below: '4.7.7', severity: 'high', ref: 'CVE-2021-23369 / CVE-2021-23383', note: 'prototype-pollution → RCE in the template compiler' }],
    axios: [
        { below: '0.21.1', severity: 'medium', ref: 'CVE-2020-28168', note: 'SSRF via redirect handling' },
        { below: '1.6.0', severity: 'medium', ref: 'CVE-2023-45857', note: 'leaks the XSRF-TOKEN to third-party hosts on cross-origin requests' },
    ],
    dompurify: [{ below: '3.0.9', severity: 'medium', ref: 'multiple mXSS bypasses (e.g. CVE-2024-45801)', note: 'mutation-XSS sanitizer bypasses — upgrade to the latest 3.x' }],
    vue: [{ below: '3.0.0', severity: 'low', ref: 'Vue 2 EOL (Dec 2023)', note: 'Vue 2.x is end-of-life; no further security patches' }],
    select2: [{ below: '4.0.6', severity: 'medium', ref: 'GHSA select2 XSS', note: 'XSS via unescaped option rendering' }],
};
// Pull {name, version} pairs from the page's script/link URLs and inline library banners. Pure + testable.
export function detectComponents(htmlText, baseUrl) {
    const urls = [
        ...H.scripts(htmlText).map((s) => resolveUrl(baseUrl, s) || s),
        ...[...htmlText.matchAll(/<link\b[^>]*href=["']([^"']+)["']/gi)].map((m) => resolveUrl(baseUrl, m[1]) || m[1]),
    ];
    const found = new Map(); // key name+version → dedup
    for (const det of DETECTORS) {
        for (const u of urls) {
            const m = det.url && u.match(det.url);
            if (m) {
                const c = { name: det.key, version: m[1], evidence: u.slice(0, 120) };
                found.set(`${c.name}@${c.version}`, c);
            }
        }
        const bm = det.banner && htmlText.match(det.banner);
        if (bm) {
            const c = { name: det.key, version: bm[1], evidence: `inline banner: ${bm[0].slice(0, 60)}` };
            found.set(`${c.name}@${c.version}`, c);
        }
    }
    return [...found.values()];
}
// Match a detected component against the vuln table; returns the applicable (most severe / lowest-fixed) entry.
export function matchVulnerabilities(c) {
    const vulns = (VULN_DB[c.name] || []).filter((v) => versionLt(c.version, v.below));
    if (!vulns.length)
        return null;
    const rank = { high: 0, medium: 1, low: 2, info: 3 };
    return vulns.sort((a, b) => rank[a.severity] - rank[b.severity])[0];
}
export async function componentChecks(ctx) {
    const out = [];
    const components = detectComponents(ctx.html, ctx.baseUrl);
    if (!components.length) {
        out.push(f('components.none', 'No fingerprintable client-side libraries', 'info', true, 'no known JS library + version detected in script/link URLs or banners', undefined));
        return out;
    }
    let vulnerable = 0;
    for (const c of components) {
        const v = matchVulnerabilities(c);
        if (v) {
            vulnerable++;
            out.push(f(`components.${c.name}`, `Outdated ${c.name} ${c.version} — ${v.ref}`, v.severity, false, `${c.name} ${c.version} is vulnerable (${v.ref}): ${v.note}. [${c.evidence}]`, `Upgrade ${c.name} to ${v.below} or later (the first version without this issue).`));
        }
        else {
            out.push(f(`components.${c.name}`, `${c.name} ${c.version} — no known vuln`, 'info', true, `${c.name} ${c.version} detected; not in the known-vulnerable range`, undefined));
        }
    }
    if (!vulnerable)
        out.push(f('components.summary', 'All detected client libraries are current', 'info', true, `${components.length} librar${components.length === 1 ? 'y' : 'ies'} detected, none in a known-vulnerable range`, undefined));
    return out;
}
