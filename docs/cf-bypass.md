# Cloudflare bot / Access bypass

For Dynamic Business probes behind Cloudflare Bot Fight Mode / WAF (and beta Access):

| Env var | Header | Scope |
|---|---|---|
| `CF_SMOKE_KEY` / `X_SMOKE_KEY` | `x-smoke-key` | Any host when set (legacy alias: `SMOKE_KEY`) |
| `CF_ACCESS_CLIENT_ID` | `CF-Access-Client-Id` | `beta.dynamicbusiness.com` only |
| `CF_ACCESS_CLIENT_SECRET` | `CF-Access-Client-Secret` | `beta.dynamicbusiness.com` only |

Implementation: [`src/cf-bypass-headers.ts`](../src/cf-bypass-headers.ts). The CLI merges these into same-origin `extraHeaders` automatically when the env vars are present. Access is **beta-only** — not www/production.

```bash
set -a; source ~/.config/db-eng/cf-bot.env; set +a
npx vibetesting-agent https://beta.dynamicbusiness.com --only security
```

CI: pass the three values as Actions secrets into `.github/workflows/probe.yml`.
