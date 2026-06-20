// src/probe.ts
// Black-box security probe for any deployed SaaS app. Given a base URL, it makes a few HTTP requests
// and evaluates security posture from the OUTSIDE (no source access) — so it works against any of our
// repos' deploys identically. Returns structured findings; the CLI turns these into a report + exit code.
import tls from 'node:tls';
const REQUIRED_HEADERS = [
    { name: 'strict-transport-security', severity: 'high', validate: (v) => /max-age=\d{5,}/.test(v), hint: 'HSTS with a long max-age' },
    { name: 'x-content-type-options', severity: 'medium', validate: (v) => v.toLowerCase().includes('nosniff'), hint: 'nosniff' },
    { name: 'referrer-policy', severity: 'low', hint: 'e.g. strict-origin-when-cross-origin' },
    { name: 'x-frame-options', severity: 'medium', hint: 'SAMEORIGIN/DENY, or a CSP frame-ancestors' },
    { name: 'content-security-policy', severity: 'high', hint: 'a Content-Security-Policy (enforced)' },
];
async function safeFetch(url, init) {
    try {
        return await fetch(url, { redirect: 'manual', ...init });
    }
    catch {
        return null;
    }
}
// Days until the served TLS certificate expires (null if it can't be determined). Uses a raw TLS
// connection because fetch() doesn't expose the peer certificate.
function tlsCertDaysRemaining(host, port = 443) {
    return new Promise((resolve) => {
        let done = false;
        const finish = (v) => { if (!done) {
            done = true;
            resolve(v);
        } };
        try {
            const socket = tls.connect({ host, port, servername: host, timeout: 8000 }, () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                if (!cert || !cert.valid_to)
                    return finish(null);
                finish(Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000));
            });
            socket.on('error', () => finish(null));
            socket.on('timeout', () => { socket.destroy(); finish(null); });
        }
        catch {
            finish(null);
        }
    });
}
// Sensitive paths that should NEVER be publicly served, with a signature so a SPA's 200+index.html
// fallback isn't a false positive — we only flag when the body actually looks like the secret file.
const SENSITIVE_PATHS = [
    { path: '/.git/HEAD', signature: /^(ref:\s|[0-9a-f]{40})/ },
    { path: '/.git/config', signature: /\[core\]/ },
    { path: '/.env', signature: /^[A-Z0-9_]+=/m },
    { path: '/.env.local', signature: /^[A-Z0-9_]+=/m },
    { path: '/.env.production', signature: /^[A-Z0-9_]+=/m },
    { path: '/.DS_Store', signature: /^Bud1/ },
];
export async function probe(baseUrl, opts = {}) {
    const findings = [];
    const u = new URL(baseUrl);
    const origin = u.origin;
    const add = (f) => findings.push(f);
    // 1) HTTPS + HTTP->HTTPS redirect.
    if (u.protocol !== 'https:') {
        add({ id: 'tls.scheme', title: 'Base URL is not HTTPS', severity: 'high', pass: false, detail: `URL uses ${u.protocol}` });
    }
    else {
        add({ id: 'tls.scheme', title: 'Served over HTTPS', severity: 'high', pass: true, detail: origin });
        const httpRes = await safeFetch(origin.replace('https:', 'http:'));
        if (httpRes) {
            const loc = httpRes.headers.get('location') || '';
            const redirects = httpRes.status >= 300 && httpRes.status < 400 && loc.startsWith('https:');
            add({ id: 'tls.redirect', title: 'HTTP redirects to HTTPS', severity: 'medium', pass: redirects, detail: redirects ? `HTTP ${httpRes.status} -> ${loc}` : `HTTP did not 3xx->https (status ${httpRes.status})` });
        }
    }
    // 2) Security response headers on the main document.
    const res = await safeFetch(origin, { redirect: 'follow' });
    if (!res) {
        add({ id: 'reachability', title: 'Could not reach the site', severity: 'high', pass: false, detail: `fetch ${origin} failed` });
        return findings;
    }
    const h = res.headers;
    for (const req of REQUIRED_HEADERS) {
        let val = h.get(req.name);
        // Allow CSP to count if only Report-Only is present (but flag it as info, not a full pass).
        if (req.name === 'content-security-policy' && !val) {
            const ro = h.get('content-security-policy-report-only');
            if (ro && opts.allowReportOnlyCsp) {
                add({ id: `header.${req.name}`, title: 'CSP present (Report-Only)', severity: 'info', pass: true, detail: 'Only Content-Security-Policy-Report-Only is set — enforce it once tuned.' });
                continue;
            }
        }
        const present = !!val;
        const valid = present && (!req.validate || req.validate(val));
        add({
            id: `header.${req.name}`,
            title: present ? `Header ${req.name}${valid ? '' : ' (weak)'}` : `Missing ${req.name}`,
            severity: req.severity,
            pass: valid,
            detail: present ? `${req.name}: ${val}`.slice(0, 200) : `expected ${req.hint}`,
        });
    }
    // 3) Information disclosure: server/x-powered-by banners.
    for (const banner of ['server', 'x-powered-by']) {
        const v = h.get(banner);
        if (v && /\d/.test(v)) {
            add({ id: `disclosure.${banner}`, title: `Version banner in ${banner}`, severity: 'low', pass: false, detail: `${banner}: ${v}` });
        }
    }
    // 4) Cookie flags (if the doc sets any cookies).
    const setCookie = h.getSetCookie?.();
    if (setCookie && setCookie.length) {
        for (const c of setCookie) {
            const name = c.split('=')[0];
            const secure = /;\s*secure/i.test(c);
            const httpOnly = /;\s*httponly/i.test(c);
            const sameSite = /;\s*samesite=/i.test(c);
            const ok = secure && httpOnly && sameSite;
            add({ id: `cookie.${name}`, title: `Cookie ${name} flags`, severity: 'medium', pass: ok, detail: `Secure=${secure} HttpOnly=${httpOnly} SameSite=${sameSite}` });
        }
    }
    // 5) security.txt (RFC 9116).
    const stPath = opts.securityTxtPath || '/.well-known/security.txt';
    const st = await safeFetch(origin + stPath, { redirect: 'follow' });
    if (st && st.ok) {
        const body = await st.text();
        const hasContact = /^contact:/im.test(body);
        const hasExpires = /^expires:/im.test(body);
        add({ id: 'securitytxt', title: 'security.txt present', severity: 'low', pass: hasContact && hasExpires, detail: hasContact && hasExpires ? 'has Contact + Expires' : 'present but missing required Contact/Expires (RFC 9116)' });
    }
    else {
        add({ id: 'securitytxt', title: 'No security.txt', severity: 'low', pass: false, detail: `expected at ${stPath}` });
    }
    // 6) CORS reflection: a misconfig where the server reflects an arbitrary Origin (esp. with credentials).
    if (opts.corsTestPath) {
        const evil = 'https://evil.example';
        const cors = await safeFetch(origin + opts.corsTestPath, { headers: { Origin: evil } });
        if (cors) {
            const acao = cors.headers.get('access-control-allow-origin') || '';
            const acac = (cors.headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
            const reflectsEvil = acao === evil;
            // Wildcard alone (no credentials) is acceptable for public endpoints; reflecting an arbitrary
            // origin WITH credentials is the dangerous combination.
            const dangerous = reflectsEvil && acac;
            add({ id: 'cors.reflection', title: 'CORS origin reflection', severity: dangerous ? 'high' : 'info', pass: !dangerous, detail: `ACAO=${acao || '(none)'} ACAC=${acac}` });
        }
    }
    // 7) TLS certificate expiry (HTTPS only).
    if (u.protocol === 'https:') {
        const days = await tlsCertDaysRemaining(u.hostname, Number(u.port) || 443);
        if (days === null) {
            add({ id: 'tls.expiry', title: 'TLS cert expiry not determinable', severity: 'info', pass: true, detail: 'could not read the peer certificate' });
        }
        else {
            const sev = days < 14 ? 'high' : days < 30 ? 'medium' : 'low';
            add({ id: 'tls.expiry', title: `TLS cert expires in ${days} day(s)`, severity: sev, pass: days >= 14, detail: days < 14 ? 'certificate expires very soon — renew now' : `${days} days remaining` });
        }
    }
    // 8) Sensitive file exposure (.git/.env/.DS_Store) — only flags when the body matches the file's
    // signature, so a SPA returning index.html for unknown paths is not a false positive.
    for (const sp of SENSITIVE_PATHS) {
        const r = await safeFetch(origin + sp.path, { redirect: 'manual' });
        if (r && r.status === 200) {
            const ct = (r.headers.get('content-type') || '').toLowerCase();
            const body = (await r.text().catch(() => '')).slice(0, 2000);
            const looksHtml = ct.includes('text/html') || /<!doctype html|<html/i.test(body);
            const exposed = !looksHtml && sp.signature.test(body);
            if (exposed)
                add({ id: `exposure${sp.path}`, title: `Exposed ${sp.path}`, severity: 'high', pass: false, detail: `${sp.path} is publicly readable` });
        }
    }
    // 9) Mixed content + 10) source-map exposure — parse the main document's HTML.
    const html = await res.clone().text().catch(() => '');
    if (html) {
        if (u.protocol === 'https:') {
            const mixed = [...html.matchAll(/\b(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)]
                .map((m) => m[1])
                .filter((x) => !/^http:\/\/(www\.w3\.org|localhost|127\.0\.0\.1)/i.test(x));
            add({ id: 'mixed-content', title: mixed.length ? `Mixed content (${mixed.length})` : 'No mixed content', severity: 'medium', pass: mixed.length === 0, detail: mixed.length ? `http:// resources on an https page, e.g. ${mixed[0]}` : 'no insecure http:// resources referenced' });
        }
        // Source maps: for each same-origin script, check if a sibling .map is served.
        const scripts = [...html.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)]
            .map((m) => m[1])
            .map((s) => { try {
            return new URL(s, origin).toString();
        }
        catch {
            return '';
        } })
            .filter((s) => s.startsWith(origin) && s.endsWith('.js'))
            .slice(0, 5);
        let mapFound = null;
        for (const js of scripts) {
            const mr = await safeFetch(js + '.map', { redirect: 'manual' });
            if (mr && mr.status === 200) {
                const b = (await mr.text().catch(() => '')).slice(0, 200);
                if (b.includes('"sources"') || b.trimStart().startsWith('{')) {
                    mapFound = js + '.map';
                    break;
                }
            }
        }
        if (scripts.length) {
            add({ id: 'sourcemaps', title: mapFound ? 'Source maps exposed' : 'No source maps exposed', severity: 'low', pass: !mapFound, detail: mapFound ? `source map served at ${mapFound} (leaks original source)` : 'no .map served for the main bundles' });
        }
    }
    return findings;
}
export function summarize(findings) {
    let passed = 0, failed = 0, failHigh = 0, failMedium = 0;
    for (const f of findings) {
        if (f.pass) {
            passed++;
            continue;
        }
        failed++;
        if (f.severity === 'high')
            failHigh++;
        if (f.severity === 'medium')
            failMedium++;
    }
    return { passed, failed, failHigh, failMedium };
}
