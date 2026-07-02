// src/testkit.ts
// Framework-agnostic helpers any repo can import into its OWN test suite (jest/vitest/node:test) to
// assert security properties white-box. These take plain functions so they don't couple to a stack.
/**
 * Cross-tenant / IDOR probe: for each case, authenticate as tenant B and try to access a resource
 * owned by tenant A. A correctly-isolated app MUST deny (401/403/404). Returns one result per case;
 * `ok=false` is a real cross-tenant access vulnerability.
 *
 * Usage (in your repo's test):
 *   const results = await idorProbe(tenantB, cases, fetch);
 *   for (const r of results) expect(r.ok, r.detail).toBe(true);
 */
export async function idorProbe(attacker, cases, fetchImpl = fetch) {
    const out = [];
    for (const c of cases) {
        const denied = c.deniedStatuses ?? [401, 403, 404];
        const { url, init } = c.request(attacker);
        const res = await fetchImpl(url, { ...init, headers: { ...init?.headers, ...attacker.headers } });
        const ok = denied.includes(res.status);
        out.push({ name: c.name, ok, status: res.status, detail: ok ? `denied (${res.status}) as expected` : `LEAK: ${attacker.label} got ${res.status} on ${c.name} — cross-tenant access` });
    }
    return out;
}
/** Assert a response's security headers (white-box). Returns the list of problems (empty = good). */
export function checkSecurityHeaders(headers, opts = {}) {
    const get = (n) => headers instanceof Headers ? headers.get(n) : (headers[n] ?? headers[n.toLowerCase()] ?? null);
    const problems = [];
    if (!/max-age=\d{5,}/.test(get('strict-transport-security') || ''))
        problems.push('missing/weak Strict-Transport-Security');
    if (!(get('x-content-type-options') || '').toLowerCase().includes('nosniff'))
        problems.push('missing X-Content-Type-Options: nosniff');
    if (!get('referrer-policy'))
        problems.push('missing Referrer-Policy');
    const csp = get('content-security-policy');
    const cspRO = get('content-security-policy-report-only');
    if (!csp && !(cspRO && !opts.requireEnforcedCsp))
        problems.push(opts.requireEnforcedCsp ? 'missing enforced Content-Security-Policy' : 'missing Content-Security-Policy (or Report-Only)');
    return problems;
}
/**
 * RBAC / auth-enforcement probe: run one protected endpoint against several actors (anonymous, wrong-role
 * user, admin, a cron-secret header, …) and assert each is allowed or denied as expected. Covers "unauth
 * ⇒ 401", "wrong role ⇒ 403", "admin-only", "premium/feature gating", and "dual-auth (bearer OR secret)".
 * `ok=false` is a real access-control violation.
 */
export async function rbacProbe(request, actors, fetchImpl = fetch) {
    const out = [];
    for (const a of actors) {
        const denied = a.deniedStatuses ?? [401, 403, 404];
        const { url, init } = request();
        const res = await fetchImpl(url, { ...init, headers: { ...init?.headers, ...a.headers } });
        const isDenied = denied.includes(res.status);
        const ok = a.expect === 'deny' ? isDenied : !isDenied;
        out.push({
            actor: a.label, ok, status: res.status,
            detail: ok
                ? `${a.expect === 'deny' ? 'denied' : 'allowed'} (${res.status}) as expected`
                : a.expect === 'deny'
                    ? `NOT DENIED: ${a.label} got ${res.status} on a protected endpoint (expected 401/403/404)`
                    : `WRONGLY DENIED: ${a.label} got ${res.status} but should be allowed`,
        });
    }
    return out;
}
/**
 * Data-isolation probe for LIST endpoints: fetch the same collection as two different users and assert
 * their resource-id sets are disjoint (neither sees the other's private rows). `extractIds` pulls the
 * ids out of a response body. `ok=false` (shared ids) means the list isn't owner-scoped.
 */
export async function dataIsolationProbe(request, a, b, extractIds, fetchImpl = fetch) {
    const fetchIds = async (who) => {
        const { url, init } = request();
        const res = await fetchImpl(url, { ...init, headers: { ...init?.headers, ...who.headers } });
        return new Set(extractIds(await res.text()));
    };
    const [idsA, idsB] = [await fetchIds(a), await fetchIds(b)];
    const shared = [...idsA].filter((id) => idsB.has(id));
    return { ok: shared.length === 0, shared, detail: shared.length ? `${a.label} and ${b.label} share ${shared.length} resource id(s) — list is not owner-scoped` : 'no shared resource ids between the two users' };
}
/**
 * Mass-assignment probe: POST/PUT a create request whose body FORGES an auth-derived field (e.g.
 * user_id/author_id/status), then assert the server ignored it — the forged value must NOT appear in the
 * response. `ok=false` means the client can set fields it shouldn't (privilege escalation / spoofing).
 */
export async function massAssignmentProbe(request, forgedValue, fetchImpl = fetch) {
    const { url, init } = request();
    const res = await fetchImpl(url, init);
    const body = await res.text();
    const reflected = body.includes(forgedValue);
    return { ok: !reflected, status: res.status, detail: reflected ? `server reflected the forged value "${forgedValue}" — field is client-writable` : 'forged field was not accepted' };
}
/** Scan a response body for sensitive field NAMES that should never be returned to a client. Pure. */
export function findSensitiveFields(body, fields = ['password', 'password_hash', 'access_token', 'accesstoken', 'refresh_token', 'secret', 'api_key', 'apikey', 'private_key', 'client_secret', 'ssn']) {
    const found = new Set();
    for (const f of fields) {
        // Match the field as a JSON key: "field": …
        if (new RegExp(`"${f.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}"\\s*:`, 'i').test(body))
            found.add(f);
    }
    return [...found];
}
// ───────────────────────────── multi-tenant / cross-tenant helpers ───────────────────────────────
// Many SaaS apps scope data by a tenant/org id passed as a query param (e.g. ?tenant_uuid=…). The classic
// separation-of-accounts bug is a backend that TRUSTS that param instead of checking the caller belongs
// to the tenant. These pure helpers drive that test; a browser recipe that captures the two sessions is
// in examples/tenant-isolation/.
/** Set (or add) a tenant id on a URL's query string. Keeps relative URLs relative. */
export function setTenantParam(url, tenantId, param = 'tenant_uuid') {
    const isAbsolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(url);
    const u = new URL(url, isAbsolute ? undefined : 'http://placeholder.invalid');
    u.searchParams.set(param, tenantId);
    return isAbsolute ? u.toString() : u.pathname + u.search + u.hash;
}
/**
 * Judge one cross-tenant probe from three observations:
 *  - baseline: the OWNER requesting their own tenant (proves what real data looks like),
 *  - attack:   the ATTACKER requesting the owner's tenant (must be denied / return nothing),
 *  - control:  the attacker requesting their OWN tenant (proves their auth works — distinguishes a real
 *              denial from a broken session).
 * Returns a verdict + human reason. `leak` = the attacker got the owner's actual data.
 */
export function classifyTenantAccess(o) {
    const { baseline, attack, control } = o;
    if (!attack)
        return { verdict: 'inconclusive', reason: 'no attacker response observed' };
    // A denial only means "isolated" if we have a WORKING session to compare against — otherwise the 401
    // might just be a stale/broken token, not real access control.
    const sessionOk = (control && control.status === 200) || (baseline && baseline.status === 200);
    if ([401, 403, 404].includes(attack.status)) {
        return sessionOk
            ? { verdict: 'isolated', reason: `cross-tenant request denied (${attack.status})` }
            : { verdict: 'inconclusive', reason: `denied (${attack.status}) but no valid session baseline — could be a stale session, not real isolation` };
    }
    if (!baseline || baseline.status !== 200)
        return { verdict: 'inconclusive', reason: 'no valid baseline — the legitimate owner request did not return 200 (stale session?)' };
    if (attack.status === 200) {
        const trivial = baseline.body.trim().length <= 2; // e.g. "{}", "[]"
        if (!trivial && attack.body === baseline.body && (!control || attack.body !== control.body)) {
            return { verdict: 'leak', reason: "attacker received the owner's exact data" };
        }
        // Genuinely empty / no-data response ⇒ isolated regardless of control.
        if (attack.body.trim().length <= 2 || /"data"\s*:\s*(null|\[\]|\{\})/.test(attack.body)) {
            return { verdict: 'isolated', reason: '200 but no owner data returned (empty response)' };
        }
        // Non-empty body: we can only call it isolated if it matches the attacker's OWN control data.
        if (control && attack.body === control.body) {
            return { verdict: 'isolated', reason: "200 returning the attacker's own-scope data, not the owner's" };
        }
        if (!control) {
            return { verdict: 'inconclusive', reason: '200 with data but no attacker-control response to compare — cannot tell own-data from a leak' };
        }
        return { verdict: 'inspect', reason: "200 with data that is neither the owner's nor the attacker's own — review manually" };
    }
    return { verdict: 'inspect', reason: `unexpected status ${attack.status}` };
}
/** Assert a Set-Cookie value carries Secure + HttpOnly + SameSite. Returns problems (empty = good). */
export function checkCookieFlags(setCookie) {
    const problems = [];
    if (!/;\s*secure/i.test(setCookie))
        problems.push('cookie missing Secure');
    if (!/;\s*httponly/i.test(setCookie))
        problems.push('cookie missing HttpOnly');
    if (!/;\s*samesite=/i.test(setCookie))
        problems.push('cookie missing SameSite');
    return problems;
}
