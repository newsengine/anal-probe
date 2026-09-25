// src/crawl-map.ts
// #42 — authenticated deep-crawl + coverage map. The foundation for real coverage: a bounded, same-origin
// BFS that (optionally authenticated via extraHeaders) discovers the actual attack surface — reachable
// endpoints, query parameters, HTML forms (action/method/fields), and referenced /api/* routes. Safe:
// GET navigation only, capped, never leaves the origin. Everything else (injection, XSS, access-control)
// tests the surface this map produces, and the coverage numbers make a scan's results meaningful.

import type { ScanOptions } from './types.js';
import { safeFetch, resolveUrl, sameOrigin, html as H } from './core.js';

export interface FormSpec { action: string; method: string; fields: string[] }
export interface CoverageMap {
  seed: string;
  origin: string;
  endpoints: string[];   // unique same-origin paths reached or referenced
  params: string[];      // unique query-parameter names seen
  forms: FormSpec[];     // HTML forms (deduped by action+method+fields)
  apis: string[];        // referenced /api|/rest/* paths
  pagesVisited: number;
  capped: boolean;       // true if a cap stopped the crawl before exhaustion
}

export interface CrawlMapOptions {
  maxPages?: number;     // default 50
  maxDepth?: number;     // default 3
  timeoutMs?: number;
  extraHeaders?: ScanOptions['extraHeaders']; // cookie/authorization for authenticated crawl (same-origin only)
}

const ASSET_EXT = /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|pdf|zip|mp4|webm)(?:$|\?)/i;

/** Parse <form> blocks into {action, method, fields}. Regex-based, tolerant, zero-dep. */
export function parseForms(baseUrl: string, htmlText: string): FormSpec[] {
  const out: FormSpec[] = [];
  for (const m of htmlText.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = m[1];
    const inner = m[2];
    const action = resolveUrl(baseUrl, (attrs.match(/\baction\s*=\s*["']([^"']*)["']/i)?.[1] || baseUrl)) || baseUrl;
    const method = (attrs.match(/\bmethod\s*=\s*["']([^"']+)["']/i)?.[1] || 'get').toLowerCase();
    const fields = new Set<string>();
    for (const fm of inner.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi)) fields.add(fm[1]);
    out.push({ action, method, fields: [...fields] });
  }
  return out;
}

const pathOf = (u: string): string => { try { return new URL(u).pathname; } catch { return u; } };

/** Bounded, same-origin BFS coverage map. Auth via opts.extraHeaders (sent same-origin only). */
export async function buildCoverageMap(seed: string, opts: CrawlMapOptions = {}): Promise<CoverageMap> {
  const maxPages = opts.maxPages ?? 50;
  const maxDepth = opts.maxDepth ?? 3;
  const origin = new URL(seed).origin;

  const endpoints = new Set<string>();
  const params = new Set<string>();
  const apis = new Set<string>();
  const formKeys = new Set<string>();
  const forms: FormSpec[] = [];

  const seen = new Set<string>();
  const queue: { url: string; depth: number }[] = [{ url: seed, depth: 0 }];
  let visited = 0;
  let capped = false;

  const record = (abs: string) => {
    if (!sameOrigin(abs, origin)) return;
    let u: URL; try { u = new URL(abs); } catch { return; }
    endpoints.add(u.pathname);
    for (const k of u.searchParams.keys()) params.add(k);
    if (/\/(?:api|rest)\//.test(u.pathname)) apis.add(u.pathname);
  };

  while (queue.length) {
    if (visited >= maxPages) { capped = queue.length > 0; break; }
    const { url, depth } = queue.shift()!;
    const norm = pathOf(url).replace(/\/+$/, '') || '/';
    if (seen.has(norm)) continue;
    seen.add(norm);

    const res = await safeFetch(url, { redirect: 'follow', headers: opts.extraHeaders }, opts.timeoutMs);
    if (!res || !res.ok) continue;
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    visited++;
    record(url);
    if (!ct.includes('html')) continue; // JSON/other endpoints are recorded but not parsed for links
    const body = (await res.text().catch(() => '')).slice(0, 2_000_000);

    for (const f of parseForms(url, body)) {
      const key = `${f.method} ${pathOf(f.action)} ${f.fields.join(',')}`;
      if (!formKeys.has(key)) { formKeys.add(key); forms.push(f); }
      record(f.action);
    }
    // Referenced /api|/rest paths in scripts/attributes (not just <a> links).
    for (const am of body.matchAll(/["'`(]((?:https?:\/\/[^"'`)\s]+)?\/(?:api|rest)\/[A-Za-z0-9._/-]+)/g)) {
      const abs = resolveUrl(url, am[1]); if (abs) record(abs);
    }
    // Follow same-origin links.
    for (const href of H.links(body)) {
      const abs = resolveUrl(url, href);
      if (!abs || !sameOrigin(abs, origin)) continue;
      if (ASSET_EXT.test(abs)) { record(abs); continue; }
      record(abs);
      if (depth < maxDepth) queue.push({ url: abs.split('#')[0], depth: depth + 1 });
    }
  }

  return {
    seed, origin,
    endpoints: [...endpoints].sort(),
    params: [...params].sort(),
    forms,
    apis: [...apis].sort(),
    pagesVisited: visited,
    capped,
  };
}

/** One-line human summary of a coverage map. */
export function summarizeCoverage(map: CoverageMap): string {
  return `coverage: ${map.pagesVisited} page(s) · ${map.endpoints.length} endpoint(s) · ${map.params.length} param(s) · ${map.forms.length} form(s) · ${map.apis.length} api route(s)${map.capped ? ' (capped)' : ''}`;
}
