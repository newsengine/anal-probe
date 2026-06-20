export interface IdorCase {
    /** Human label for the resource/endpoint under test. */
    name: string;
    /** Build the request for a given tenant's auth. Return {url, init} for fetch. */
    request: (auth: TenantAuth) => {
        url: string;
        init?: RequestInit;
    };
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
export declare function idorProbe(attacker: TenantAuth, cases: IdorCase[], fetchImpl?: typeof fetch): Promise<IdorResult[]>;
/** Assert a response's security headers (white-box). Returns the list of problems (empty = good). */
export declare function checkSecurityHeaders(headers: Headers | Record<string, string>, opts?: {
    requireEnforcedCsp?: boolean;
}): string[];
/** Assert a Set-Cookie value carries Secure + HttpOnly + SameSite. Returns problems (empty = good). */
export declare function checkCookieFlags(setCookie: string): string[];
