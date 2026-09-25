/**
 * Cloudflare bot-exception headers for Dynamic Business (and similar) probes.
 *
 * Host gates (never attach secrets to third-party origins):
 * - `x-smoke-key` from `CF_SMOKE_KEY` | `X_SMOKE_KEY` (legacy: `SMOKE_KEY`) only
 *   when the request host is `dynamicbusiness.com` or `*.dynamicbusiness.com`.
 * - Cloudflare Access service-token headers only when hostname is exactly
 *   `beta.dynamicbusiness.com` and `CF_ACCESS_CLIENT_ID` +
 *   `CF_ACCESS_CLIENT_SECRET` are set.
 *
 * For HTTP/fetch callers: use `cfBypassHeaders(url)` / `withCfBypassHeaders` per URL.
 * For Playwright browsers: use `installCfBypassRoute(context)` — never put these
 * secrets on context-global `extraHTTPHeaders` (leaks to every origin).
 *
 * Secrets must come from env / CI secrets — never hardcode. Access is beta-only.
 */
export const BETA_ACCESS_HOST = 'beta.dynamicbusiness.com';
function hostnameOf(raw) {
    if (!raw)
        return '';
    try {
        const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
        return new URL(withScheme).hostname.toLowerCase();
    }
    catch {
        return '';
    }
}
/** First-party Dynamic Business hosts that may receive `x-smoke-key`. */
export function isSmokeKeyHost(host) {
    const h = (host || '').toLowerCase();
    return h === 'dynamicbusiness.com' || h.endsWith('.dynamicbusiness.com');
}
/** Exact beta host that may receive Cloudflare Access service-token headers. */
export function isBetaAccessHost(host) {
    return (host || '').toLowerCase() === BETA_ACCESS_HOST;
}
/** Build CF bypass headers when the matching env vars are set for `targetUrl`. */
export function cfBypassHeaders(targetUrl) {
    const headers = {};
    const host = hostnameOf(targetUrl);
    if (!host)
        return headers;
    const smoke = process.env.CF_SMOKE_KEY || process.env.X_SMOKE_KEY || process.env.SMOKE_KEY;
    if (smoke && isSmokeKeyHost(host))
        headers['x-smoke-key'] = smoke;
    if (isBetaAccessHost(host)) {
        const id = process.env.CF_ACCESS_CLIENT_ID;
        const secret = process.env.CF_ACCESS_CLIENT_SECRET;
        if (id)
            headers['CF-Access-Client-Id'] = id;
        if (secret)
            headers['CF-Access-Client-Secret'] = secret;
    }
    return headers;
}
/** Merge env-derived CF bypass headers under explicit headers (explicit wins). */
export function withCfBypassHeaders(targetUrl, explicit) {
    const merged = { ...cfBypassHeaders(targetUrl), ...(explicit || {}) };
    return Object.keys(merged).length ? merged : undefined;
}
/**
 * Playwright BrowserContext route: inject CF bypass headers only when the
 * request URL hostname matches the smoke / Access gates. Third-party
 * subrequests never receive secrets.
 */
export async function installCfBypassRoute(context) {
    await context.route('**/*', async (route) => {
        const req = route.request();
        const bypass = cfBypassHeaders(req.url());
        if (!Object.keys(bypass).length) {
            await route.continue();
            return;
        }
        await route.continue({
            headers: {
                ...req.headers(),
                ...bypass,
            },
        });
    });
}
