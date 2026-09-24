// src/servercve.ts
// #36 (scoped) — correlate a DISCLOSED server/runtime version banner against a curated table of
// high-signal, black-box-relevant CVEs. This is the honest black-box slice of CVE coverage: we can only
// act on versions the server actually advertises (Server / X-Powered-By), and we keep the table curated
// and low-false-positive (exact product + affected-version predicate) rather than pretending to "run all
// CVEs". On-demand NVD keyword lookup for anything else stays in `cve` mode (src/cve.ts).

import type { Finding, ScanContext, Severity } from './types.js';
import { parseVersion } from './components.js';

export interface ServerCve { product: RegExp; cve: string; severity: Severity; affected: (v: string) => boolean; note: string; fix: string }

const lt = (v: string, b: string) => { const a = parseVersion(v), c = parseVersion(b); for (let i = 0; i < 3; i++) { if ((a[i] || 0) !== (c[i] || 0)) return (a[i] || 0) < (c[i] || 0); } return false; };
const between = (v: string, lo: string, hi: string) => !lt(v, lo) && lt(v, hi); // [lo, hi)

// Curated high-signal server/runtime CVEs that matter from a black-box banner. Kept small + exact.
export const SERVER_CVES: ServerCve[] = [
  { product: /apache/i, cve: 'CVE-2021-41773', severity: 'high', affected: (v) => v === '2.4.49', note: 'Apache httpd 2.4.49 path traversal + RCE', fix: 'Upgrade Apache httpd to 2.4.51+.' },
  { product: /apache/i, cve: 'CVE-2021-42013', severity: 'high', affected: (v) => v === '2.4.49' || v === '2.4.50', note: 'Apache httpd 2.4.49/2.4.50 path traversal + RCE', fix: 'Upgrade Apache httpd to 2.4.51+.' },
  { product: /nginx/i, cve: 'CVE-2019-20372', severity: 'medium', affected: (v) => between(v, '0.0.0', '1.17.7'), note: 'nginx <1.17.7 error_page request smuggling', fix: 'Upgrade nginx to 1.17.7+.' },
  { product: /openssh/i, cve: 'CVE-2024-6387', severity: 'high', affected: (v) => between(v, '8.5', '9.8'), note: 'OpenSSH 8.5–9.7 "regreSSHion" RCE', fix: 'Upgrade OpenSSH to 9.8p1+.' },
  { product: /openssl/i, cve: 'CVE-2022-3602', severity: 'high', affected: (v) => between(v, '3.0.0', '3.0.7'), note: 'OpenSSL 3.0.0–3.0.6 X.509 buffer overflow', fix: 'Upgrade OpenSSL to 3.0.7+.' },
  { product: /php/i, cve: 'CVE-2019-11043', severity: 'high', affected: (v) => between(v, '7.1.0', '7.3.11'), note: 'PHP-FPM <7.3.11 remote code execution', fix: 'Upgrade PHP to 7.3.11+ (or 7.2.24+/7.1.33+).' },
];

/** Product + version pairs advertised in Server / X-Powered-By headers (e.g. "nginx/1.18.0", "Apache/2.4.49 (Ubuntu)"). */
export function parseServerBanners(ctx: ScanContext): { product: string; version: string; raw: string }[] {
  const out: { product: string; version: string; raw: string }[] = [];
  for (const name of ['server', 'x-powered-by']) {
    const raw = ctx.headers.get(name);
    if (!raw) continue;
    for (const m of raw.matchAll(/([A-Za-z][A-Za-z0-9_+-]*)\/(\d+(?:\.\d+){1,3})/g)) out.push({ product: m[1], version: m[2], raw });
  }
  return out;
}

/** category 'components': flag any disclosed server/runtime version that matches a curated CVE. */
export function serverCveFindings(ctx: ScanContext): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const b of parseServerBanners(ctx)) {
    for (const c of SERVER_CVES) {
      if (!c.product.test(b.product)) continue;
      if (!c.affected(b.version)) continue;
      if (seen.has(c.cve)) continue;
      seen.add(c.cve);
      out.push({
        category: 'components', id: `components.server-cve.${c.cve}`,
        title: `${b.product} ${b.version} — ${c.cve}`, severity: c.severity, pass: false,
        detail: `${c.note} — advertised via "${b.raw.slice(0, 80)}"`, fix: c.fix,
      });
    }
  }
  return out;
}
