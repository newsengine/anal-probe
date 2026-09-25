# Cloudflare bot / Access bypass

For Dynamic Business probes behind Cloudflare Bot Fight Mode / WAF (and beta Access):

| Env var | Header | Scope |
|---|---|---|
| `CF_SMOKE_KEY` / `X_SMOKE_KEY` | `x-smoke-key` | `dynamicbusiness.com` and `*.dynamicbusiness.com` only (legacy alias: `SMOKE_KEY`) |
| `CF_ACCESS_CLIENT_ID` | `CF-Access-Client-Id` | exact `beta.dynamicbusiness.com` only |
| `CF_ACCESS_CLIENT_SECRET` | `CF-Access-Client-Secret` | exact `beta.dynamicbusiness.com` only |

Implementation: [`src/cf-bypass-headers.ts`](../src/cf-bypass-headers.ts).

- **HTTP / CLI scan:** merges into same-origin `extraHeaders` via `withCfBypassHeaders(url)` (per target URL).
- **Browser (`browse`):** uses `installCfBypassRoute(context)` — host-filtered per request. Never puts Access/smoke secrets on context-global `extraHTTPHeaders` (those would leak to third-party fonts/CDNs).

Access is **beta-only** — not www/production.

```bash
set -a; source ~/.config/db-eng/cf-bot.env; set +a
npx vibetesting-agent https://beta.dynamicbusiness.com --only security
```

CI: pass the three values as Actions secrets into `.github/workflows/probe.yml`.
