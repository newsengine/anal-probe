// src/testkit.ts
// Framework-agnostic helpers any repo can import into its OWN test suite (jest/vitest/node:test) to
// assert security properties white-box. These take plain functions so they don't couple to a stack.

export interface IdorCase {
  /** Human label for the resource/endpoint under test. */
  name: string;
  /** Build the request for a given tenant's auth. Return {url, init} for fetch. */
  request: (auth: TenantAuth) => { url: string; init?: RequestInit };
  /** Status codes that mean "correctly denied" (default: 401, 403, 404). */
  deniedStatuses?: number[];
}
export interface TenantAuth {
  label: string;
  /** Headers/cookies that authenticate as this tenant. */
  headers: Record<string, string>;
}
export interface IdorResult {
  name: string;
  ok: boolean;
  status: number;
  detail: string;
}

/**
 * Cross-tenant / IDOR probe: for each case, authenticate as tenant B and try to access a resource
 * owned by tenant A. A correctly-isolated app MUST deny (401/403/404). Returns one result per case;
 * `ok=false` is a real cross-tenant access vulnerability.
 *
 * Usage (in your repo's test):
 *   const results = await idorProbe(tenantB, cases, fetch);
 *   for (const r of results) expect(r.ok, r.detail).toBe(true);
 */
export async function idorProbe(
  attacker: TenantAuth,
  cases: IdorCase[],
  fetchImpl: typeof fetch = fetch,
): Promise<IdorResult[]> {
  const out: IdorResult[] = [];
  for (const c of cases) {
    const denied = c.deniedStatuses ?? [401, 403, 404];
    const { url, init } = c.request(attacker);
    const res = await fetchImpl(url, { ...init, headers: { ...(init?.headers as any), ...attacker.headers } });
    const ok = denied.includes(res.status);
    out.push({ name: c.name, ok, status: res.status, detail: ok ? `denied (${res.status}) as expected` : `LEAK: ${attacker.label} got ${res.status} on ${c.name} — cross-tenant access` });
  }
  return out;
}

/** Assert a response's security headers (white-box). Returns the list of problems (empty = good). */
export function checkSecurityHeaders(
  headers: Headers | Record<string, string>,
  opts: { requireEnforcedCsp?: boolean } = {},
): string[] {
  const get = (n: string) =>
    headers instanceof Headers ? headers.get(n) : (headers[n] ?? headers[n.toLowerCase()] ?? null);
  const problems: string[] = [];
  if (!/max-age=\d{5,}/.test(get('strict-transport-security') || '')) problems.push('missing/weak Strict-Transport-Security');
  if (!(get('x-content-type-options') || '').toLowerCase().includes('nosniff')) problems.push('missing X-Content-Type-Options: nosniff');
  if (!get('referrer-policy')) problems.push('missing Referrer-Policy');
  const csp = get('content-security-policy');
  const cspRO = get('content-security-policy-report-only');
  if (!csp && !(cspRO && !opts.requireEnforcedCsp)) problems.push(opts.requireEnforcedCsp ? 'missing enforced Content-Security-Policy' : 'missing Content-Security-Policy (or Report-Only)');
  return problems;
}

// ───────────────────────────── multi-tenant / cross-tenant helpers ───────────────────────────────
// Many SaaS apps scope data by a tenant/org id passed as a query param (e.g. ?tenant_uuid=…). The classic
// separation-of-accounts bug is a backend that TRUSTS that param instead of checking the caller belongs
// to the tenant. These pure helpers drive that test; a browser recipe that captures the two sessions is
// in examples/tenant-isolation/.

/** Set (or add) a tenant id on a URL's query string. Keeps relative URLs relative. */
export function setTenantParam(url: string, tenantId: string, param = 'tenant_uuid'): string {
  const isAbsolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(url);
  const u = new URL(url, isAbsolute ? undefined : 'http://placeholder.invalid');
  u.searchParams.set(param, tenantId);
  return isAbsolute ? u.toString() : u.pathname + u.search;
}

export interface TenantProbeResponse { status: number; body: string }
export type TenantVerdict = 'isolated' | 'leak' | 'inspect' | 'inconclusive';

/**
 * Judge one cross-tenant probe from three observations:
 *  - baseline: the OWNER requesting their own tenant (proves what real data looks like),
 *  - attack:   the ATTACKER requesting the owner's tenant (must be denied / return nothing),
 *  - control:  the attacker requesting their OWN tenant (proves their auth works — distinguishes a real
 *              denial from a broken session).
 * Returns a verdict + human reason. `leak` = the attacker got the owner's actual data.
 */
export function classifyTenantAccess(o: {
  baseline?: TenantProbeResponse; attack?: TenantProbeResponse; control?: TenantProbeResponse;
}): { verdict: TenantVerdict; reason: string } {
  const { baseline, attack, control } = o;
  if (!attack) return { verdict: 'inconclusive', reason: 'no attacker response observed' };
  // A denial only means "isolated" if we have a WORKING session to compare against — otherwise the 401
  // might just be a stale/broken token, not real access control.
  const sessionOk = (control && control.status === 200) || (baseline && baseline.status === 200);
  if ([401, 403, 404].includes(attack.status)) {
    return sessionOk
      ? { verdict: 'isolated', reason: `cross-tenant request denied (${attack.status})` }
      : { verdict: 'inconclusive', reason: `denied (${attack.status}) but no valid session baseline — could be a stale session, not real isolation` };
  }
  if (!baseline || baseline.status !== 200) return { verdict: 'inconclusive', reason: 'no valid baseline — the legitimate owner request did not return 200 (stale session?)' };
  if (attack.status === 200) {
    const trivial = baseline.body.trim().length <= 2; // e.g. "{}", "[]"
    if (!trivial && attack.body === baseline.body && (!control || attack.body !== control.body)) {
      return { verdict: 'leak', reason: "attacker received the owner's exact data" };
    }
    if (!control || attack.body === control.body || attack.body.trim().length <= 2 || /"data"\s*:\s*(null|\[\]|\{\})/.test(attack.body)) {
      return { verdict: 'isolated', reason: '200 but no owner data returned (empty / own-scope)' };
    }
    return { verdict: 'inspect', reason: "200 with data that is neither the owner's nor the attacker's own — review manually" };
  }
  return { verdict: 'inspect', reason: `unexpected status ${attack.status}` };
}

/** Assert a Set-Cookie value carries Secure + HttpOnly + SameSite. Returns problems (empty = good). */
export function checkCookieFlags(setCookie: string): string[] {
  const problems: string[] = [];
  if (!/;\s*secure/i.test(setCookie)) problems.push('cookie missing Secure');
  if (!/;\s*httponly/i.test(setCookie)) problems.push('cookie missing HttpOnly');
  if (!/;\s*samesite=/i.test(setCookie)) problems.push('cookie missing SameSite');
  return problems;
}
