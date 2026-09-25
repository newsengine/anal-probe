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

function hostnameOf(raw?: string): string {
  if (!raw) return '';
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
    return new URL(withScheme).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/** Build CF bypass headers when the matching env vars are set for `targetUrl`. */
export function cfBypassHeaders(targetUrl?: string): Record<string, string> {
  const headers: Record<string, string> = {};

  const smoke = process.env.CF_SMOKE_KEY || process.env.X_SMOKE_KEY || process.env.SMOKE_KEY;
  if (smoke) headers['x-smoke-key'] = smoke;

  const host = hostnameOf(targetUrl);
  if (host === 'beta.dynamicbusiness.com') {
    const id = process.env.CF_ACCESS_CLIENT_ID;
    const secret = process.env.CF_ACCESS_CLIENT_SECRET;
    if (id) headers['CF-Access-Client-Id'] = id;
    if (secret) headers['CF-Access-Client-Secret'] = secret;
  }

  return headers;
}

/** Merge env-derived CF bypass headers under explicit headers (explicit wins). */
export function withCfBypassHeaders(
  targetUrl: string | undefined,
  explicit?: Record<string, string>,
): Record<string, string> | undefined {
  const merged = { ...cfBypassHeaders(targetUrl), ...(explicit || {}) };
  return Object.keys(merged).length ? merged : undefined;
}
