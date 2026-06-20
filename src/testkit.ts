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

/** Assert a Set-Cookie value carries Secure + HttpOnly + SameSite. Returns problems (empty = good). */
export function checkCookieFlags(setCookie: string): string[] {
  const problems: string[] = [];
  if (!/;\s*secure/i.test(setCookie)) problems.push('cookie missing Secure');
  if (!/;\s*httponly/i.test(setCookie)) problems.push('cookie missing HttpOnly');
  if (!/;\s*samesite=/i.test(setCookie)) problems.push('cookie missing SameSite');
  return problems;
}
