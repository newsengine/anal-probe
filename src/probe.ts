// src/probe.ts
// Black-box security probe for any deployed SaaS app. Given a base URL, it makes a few HTTP requests
// and evaluates security posture from the OUTSIDE (no source access) — so it works against any of our
// repos' deploys identically. Returns structured findings; the CLI turns these into a report + exit code.

export type Severity = 'high' | 'medium' | 'low' | 'info';
export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  pass: boolean;
  detail: string;
}
export interface ProbeOptions {
  /** Paths expected to exist for the security.txt / CORS checks. */
  securityTxtPath?: string; // default /.well-known/security.txt
  /** An API path to test CORS reflection against (should be a CORS-enabled endpoint). */
  corsTestPath?: string;
  /** Treat these missing headers as info (not fail) — e.g. CSP if you only ship Report-Only. */
  allowReportOnlyCsp?: boolean;
}

const REQUIRED_HEADERS: { name: string; severity: Severity; validate?: (v: string) => boolean; hint: string }[] = [
  { name: 'strict-transport-security', severity: 'high', validate: (v) => /max-age=\d{5,}/.test(v), hint: 'HSTS with a long max-age' },
  { name: 'x-content-type-options', severity: 'medium', validate: (v) => v.toLowerCase().includes('nosniff'), hint: 'nosniff' },
  { name: 'referrer-policy', severity: 'low', hint: 'e.g. strict-origin-when-cross-origin' },
  { name: 'x-frame-options', severity: 'medium', hint: 'SAMEORIGIN/DENY, or a CSP frame-ancestors' },
  { name: 'content-security-policy', severity: 'high', hint: 'a Content-Security-Policy (enforced)' },
];

async function safeFetch(url: string, init?: RequestInit): Promise<Response | null> {
  try {
    return await fetch(url, { redirect: 'manual', ...init });
  } catch {
    return null;
  }
}

export async function probe(baseUrl: string, opts: ProbeOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];
  const u = new URL(baseUrl);
  const origin = u.origin;
  const add = (f: Finding) => findings.push(f);

  // 1) HTTPS + HTTP->HTTPS redirect.
  if (u.protocol !== 'https:') {
    add({ id: 'tls.scheme', title: 'Base URL is not HTTPS', severity: 'high', pass: false, detail: `URL uses ${u.protocol}` });
  } else {
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
    const valid = present && (!req.validate || req.validate(val!));
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
  const setCookie = (h as any).getSetCookie?.() as string[] | undefined;
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
  } else {
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

  return findings;
}

export function summarize(findings: Finding[]): { passed: number; failed: number; failHigh: number; failMedium: number } {
  let passed = 0, failed = 0, failHigh = 0, failMedium = 0;
  for (const f of findings) {
    if (f.pass) { passed++; continue; }
    failed++;
    if (f.severity === 'high') failHigh++;
    if (f.severity === 'medium') failMedium++;
  }
  return { passed, failed, failHigh, failMedium };
}
