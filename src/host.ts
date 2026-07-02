// src/host.ts
// PASSIVE host / infrastructure intelligence: what sits behind the URL. Resolves the IP(s), reverse-DNS,
// and fingerprints the CDN / hosting provider from response headers. All passive (DNS lookups + the
// headers we already fetched) — NO port scanning, NO service probing, NO attack traffic. The key insight
// it surfaces: most modern deploys sit behind a CDN, so the resolved IP is an edge node (Cloudflare/
// Vercel/…), not the origin server — which is exactly what you'd need to know before any host-level work.

import { promises as dns } from 'node:dns';
import type { Finding, ScanContext, Severity } from './types.js';

const f = (id: string, title: string, severity: Severity, pass: boolean, detail: string, fix?: string): Finding =>
  ({ category: 'host', id, title, severity, pass, detail, fix });

interface EdgeSig { name: string; cdn: boolean; test: (h: (n: string) => string) => boolean }

// Header fingerprints for common edges/hosts. `cdn:true` means the resolved IP is an edge, not the origin.
const EDGE_SIGS: EdgeSig[] = [
  { name: 'Cloudflare', cdn: true, test: (h) => /cloudflare/i.test(h('server')) || !!h('cf-ray') },
  { name: 'Vercel', cdn: true, test: (h) => /vercel/i.test(h('server')) || !!h('x-vercel-id') },
  { name: 'Netlify', cdn: true, test: (h) => /netlify/i.test(h('server')) || !!h('x-nf-request-id') },
  { name: 'AWS CloudFront', cdn: true, test: (h) => /cloudfront/i.test(h('via')) || !!h('x-amz-cf-id') },
  { name: 'Fastly', cdn: true, test: (h) => !!h('x-served-by') || /fastly/i.test(h('x-cache') + h('via')) },
  { name: 'Akamai', cdn: true, test: (h) => /akamai/i.test(h('server')) || !!h('x-akamai-transformed') },
  { name: 'GitHub Pages', cdn: true, test: (h) => /github\.com/i.test(h('server')) || !!h('x-github-request-id') },
  { name: 'Fly.io', cdn: false, test: (h) => !!h('fly-request-id') || /fly\//i.test(h('server')) },
  { name: 'Google Frontend', cdn: true, test: (h) => /gws|gse|google frontend/i.test(h('server')) || /google/i.test(h('via')) },
  { name: 'Nginx', cdn: false, test: (h) => /nginx/i.test(h('server')) },
  { name: 'Apache', cdn: false, test: (h) => /apache/i.test(h('server')) },
];

/** Fingerprint the edge/host from response headers. Pure/testable. */
export function identifyEdge(headers: Headers | Record<string, string>): { providers: string[]; behindCdn: boolean } {
  const h = (n: string) => (headers instanceof Headers ? headers.get(n) : (headers[n] ?? headers[n.toLowerCase()])) || '';
  const matched = EDGE_SIGS.filter((s) => { try { return s.test(h); } catch { return false; } });
  return { providers: matched.map((s) => s.name), behindCdn: matched.some((s) => s.cdn) };
}

export async function hostChecks(ctx: ScanContext): Promise<Finding[]> {
  if (!ctx.res) return [];
  const out: Finding[] = [];
  const host = ctx.url.hostname;

  // A / AAAA records (fail soft).
  const [a, aaaa] = await Promise.all([
    dns.resolve4(host).catch(() => [] as string[]),
    dns.resolve6(host).catch(() => [] as string[]),
  ]);
  const ips = [...a, ...aaaa];
  out.push(f('host.ip', ips.length ? `Resolves to ${ips.length} IP(s)` : 'No A/AAAA records', 'info', true, ips.length ? ips.slice(0, 6).join(', ') : `no address records for ${host}`));

  // Reverse DNS on the first IP — often reveals the hosting provider.
  if (a[0]) {
    const ptr = await dns.reverse(a[0]).catch(() => [] as string[]);
    if (ptr.length) out.push(f('host.ptr', 'Reverse DNS', 'info', true, `${a[0]} → ${ptr.slice(0, 3).join(', ')}`));
  }

  // Edge / hosting provider from headers.
  const { providers, behindCdn } = identifyEdge(ctx.headers);
  out.push(f('host.provider', providers.length ? `Served via ${providers.join(', ')}` : 'Hosting provider not identified from headers', 'info', true, providers.length ? `header fingerprint: ${providers.join(', ')}` : 'no distinctive edge/server headers'));

  // The load-bearing insight for anyone thinking about host-level testing.
  if (behindCdn) {
    out.push(f('host.cdn', 'Origin sits behind a CDN/edge', 'info', true, `the resolved IP(s) are ${providers.join('/')} edge nodes, not your origin server — host/port scanning them scans the CDN (and usually violates its ToS), not your app`));
  } else if (ips.length) {
    out.push(f('host.exposed', 'No CDN detected — the resolved IP may be the origin', 'low', false, 'responses show no CDN/edge fingerprint, so the A record may point straight at your server', 'Consider fronting the origin with a CDN/WAF (Cloudflare/Fastly/etc.) so the server IP isn\'t directly exposed to scanning and DDoS.'));
  }

  return out;
}
