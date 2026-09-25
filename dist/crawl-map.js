// src/crawl-map.ts
// #42 — authenticated deep-crawl + coverage map. The foundation for real coverage: a bounded, same-origin
// BFS that (optionally authenticated via extraHeaders) discovers the actual attack surface — reachable
// endpoints, query parameters, HTML forms (action/method/fields), and referenced /api/* routes. Safe:
// GET navigation only, capped, never leaves the origin. Everything else (injection, XSS, access-control)
// tests the surface this map produces, and the coverage numbers make a scan's results meaningful.
import { safeFetch, resolveUrl, sameOrigin, html as H } from './core.js';
const ASSET_EXT = /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|pdf|zip|mp4|webm)(?:$|\?)/i;
/** Parse <form> blocks into {action, method, fields}. Regex-based, tolerant, zero-dep. */
export function parseForms(baseUrl, htmlText) {
    const out = [];
    for (const m of htmlText.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
        const attrs = m[1];
        const inner = m[2];
        const action = resolveUrl(baseUrl, (attrs.match(/\baction\s*=\s*["']([^"']*)["']/i)?.[1] || baseUrl)) || baseUrl;
        const method = (attrs.match(/\bmethod\s*=\s*["']([^"']+)["']/i)?.[1] || 'get').toLowerCase();
        const fields = new Set();
        for (const fm of inner.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi))
            fields.add(fm[1]);
        out.push({ action, method, fields: [...fields] });
    }
    return out;
}
const pathOf = (u) => { try {
    return new URL(u).pathname;
}
catch {
    return u;
} };
/** Bounded, same-origin BFS coverage map. Auth via opts.extraHeaders (sent same-origin only). */
export async function buildCoverageMap(seed, opts = {}) {
    const maxPages = opts.maxPages ?? 50;
    const maxDepth = opts.maxDepth ?? 3;
    const origin = new URL(seed).origin;
    const endpoints = new Set();
    const params = new Set();
    const apis = new Set();
    const formKeys = new Set();
    const forms = [];
    const paramUrlKeys = new Set();
    const paramUrls = [];
    const seen = new Set();
    const queue = [{ url: seed, depth: 0 }];
    let visited = 0;
    let capped = false;
    const record = (abs) => {
        if (!sameOrigin(abs, origin))
            return;
        let u;
        try {
            u = new URL(abs);
        }
        catch {
            return;
        }
        endpoints.add(u.pathname);
        const keys = [...u.searchParams.keys()];
        for (const k of keys)
            params.add(k);
        if (/\/(?:api|rest)\//.test(u.pathname))
            apis.add(u.pathname);
        if (keys.length) {
            const key = u.pathname + '?' + keys.slice().sort().join(',');
            if (!paramUrlKeys.has(key)) {
                paramUrlKeys.add(key);
                if (paramUrls.length < 100)
                    paramUrls.push(u.toString());
            }
        }
    };
    while (queue.length) {
        if (visited >= maxPages) {
            capped = queue.length > 0;
            break;
        }
        const { url, depth } = queue.shift();
        const norm = pathOf(url).replace(/\/+$/, '') || '/';
        if (seen.has(norm))
            continue;
        seen.add(norm);
        const res = await safeFetch(url, { redirect: 'follow', headers: opts.extraHeaders }, opts.timeoutMs);
        if (!res || !res.ok)
            continue;
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        visited++;
        record(url);
        if (!ct.includes('html'))
            continue; // JSON/other endpoints are recorded but not parsed for links
        const body = (await res.text().catch(() => '')).slice(0, 2_000_000);
        for (const f of parseForms(url, body)) {
            const key = `${f.method} ${pathOf(f.action)} ${f.fields.join(',')}`;
            if (!formKeys.has(key)) {
                formKeys.add(key);
                forms.push(f);
            }
            record(f.action);
        }
        // Referenced /api|/rest paths in scripts/attributes (not just <a> links).
        for (const am of body.matchAll(/["'`(]((?:https?:\/\/[^"'`)\s]+)?\/(?:api|rest)\/[A-Za-z0-9._/-]+)/g)) {
            const abs = resolveUrl(url, am[1]);
            if (abs)
                record(abs);
        }
        // Follow same-origin links.
        for (const href of H.links(body)) {
            const abs = resolveUrl(url, href);
            if (!abs || !sameOrigin(abs, origin))
                continue;
            if (ASSET_EXT.test(abs)) {
                record(abs);
                continue;
            }
            record(abs);
            if (depth < maxDepth)
                queue.push({ url: abs.split('#')[0], depth: depth + 1 });
        }
    }
    return {
        seed, origin,
        endpoints: [...endpoints].sort(),
        params: [...params].sort(),
        forms,
        apis: [...apis].sort(),
        paramUrls,
        pagesVisited: visited,
        capped,
    };
}
/** One-line human summary of a coverage map. */
export function summarizeCoverage(map) {
    return `coverage: ${map.pagesVisited} page(s) · ${map.endpoints.length} endpoint(s) · ${map.params.length} param(s) · ${map.forms.length} form(s) · ${map.apis.length} api route(s)${map.capped ? ' (capped)' : ''}`;
}
