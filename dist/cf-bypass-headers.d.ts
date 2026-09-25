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
export declare const BETA_ACCESS_HOST = "beta.dynamicbusiness.com";
/** First-party Dynamic Business hosts that may receive `x-smoke-key`. */
export declare function isSmokeKeyHost(host: string): boolean;
/** Exact beta host that may receive Cloudflare Access service-token headers. */
export declare function isBetaAccessHost(host: string): boolean;
/** Build CF bypass headers when the matching env vars are set for `targetUrl`. */
export declare function cfBypassHeaders(targetUrl?: string): Record<string, string>;
/** Merge env-derived CF bypass headers under explicit headers (explicit wins). */
export declare function withCfBypassHeaders(targetUrl: string | undefined, explicit?: Record<string, string>): Record<string, string> | undefined;
type RouteLike = {
    request: () => {
        url: () => string;
        headers: () => Record<string, string>;
    };
    continue: (options?: {
        headers?: Record<string, string>;
    }) => Promise<void>;
};
type ContextLike = {
    route: (url: string, handler: (route: RouteLike) => Promise<void>) => Promise<void>;
};
/**
 * Playwright BrowserContext route: inject CF bypass headers only when the
 * request URL hostname matches the smoke / Access gates. Third-party
 * subrequests never receive secrets.
 */
export declare function installCfBypassRoute(context: ContextLike): Promise<void>;
export {};
