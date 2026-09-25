/**
 * Cloudflare bot-exception headers for Dynamic Business (and similar) probes.
 *
 * - `x-smoke-key` from `CF_SMOKE_KEY` | `X_SMOKE_KEY` (legacy: `SMOKE_KEY`) when set.
 * - Cloudflare Access service-token headers only when the target host is
 *   `beta.dynamicbusiness.com` and `CF_ACCESS_CLIENT_ID` +
 *   `CF_ACCESS_CLIENT_SECRET` are set.
 *
 * Secrets must come from env / CI secrets — never hardcode. Access is beta-only.
 */
/** Build CF bypass headers when the matching env vars are set for `targetUrl`. */
export declare function cfBypassHeaders(targetUrl?: string): Record<string, string>;
/** Merge env-derived CF bypass headers under explicit headers (explicit wins). */
export declare function withCfBypassHeaders(targetUrl: string | undefined, explicit?: Record<string, string>): Record<string, string> | undefined;
