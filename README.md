# @newsengine/anal-probe

**Point it at any deployed app and it tells you everything wrong with it** — leaked API keys in your
JS bundle, an exposed `.env`/`.git`, broken links, missing security headers, SEO/accessibility/perf
gaps. One command, **zero install**, no source access, no headless browser:

```bash
npx github:newsengine/anal-probe https://your-app.example.com
```

Built for vibe coders shipping with AI: you don't need to know what to look for — the scanner does, and
every failing finding comes with a one-line **fix**. Exits non-zero so it doubles as a CI gate.

- **Full black-box scan** — 7 categories (below), all from a URL.
- **White-box helpers** (`idorProbe`, `checkSecurityHeaders`, `checkCookieFlags`, `scanSecrets`): import
  into your own test suite (jest/vitest/node:test) for cross-tenant/IDOR + header/cookie/secret assertions.
- **Templates**: `SECURITY.md`, `security.txt`, `CODEOWNERS`.
- **Reusable GitHub Actions workflow**: `.github/workflows/probe.yml` (call it with `uses:`).

## What it checks (black-box, from just a URL)

Scope it with `--only <cats>` / `--skip <cats>` (comma-separated category names).

### 🔑 `secrets` — keys you accidentally shipped to the browser
Fetches the page **and every same-origin script bundle** and scans for real secrets: `sk_live`/`rk_live`
(Stripe), `AKIA…` (AWS), Google/SendGrid/Twilio/Anthropic/OpenAI keys, GitHub & Slack tokens, PEM
private-key blocks, and **Supabase `service_role`** JWTs (decoded + confirmed, not just pattern-matched).
Things that are *meant* to be public (Stripe `pk_live`, Supabase `anon`) are deliberately ignored.
Also flags **publicly downloadable source maps** (your unminified source). Secrets are redacted in output.

### 📂 `exposure` — config & debug surfaces that shouldn't be reachable
`/.env`(+`.local`/`.production`), `/.git/config` + `/.git/HEAD`, `/wrangler.toml`, `/.npmrc`,
`/docker-compose.yml`, `/.DS_Store`, `/backup.sql`, `package.json`. Each one **validates the body**
(not just a 200) so SPA catch-all routes don't false-positive. Plus: **stack-trace/internal-path leakage**
on error pages, and **GraphQL introspection** left enabled.

### 🔗 `reliability` — is it actually working?
Homepage status, **broken same-origin links & images** (sampled HEAD/GET), and **mixed content**
(`http://` resources on an `https://` page).

### 🔐 `security` — headers / TLS / CORS / cookies
HTTPS + HTTP→HTTPS redirect, **HSTS**, **`nosniff`**, **`Referrer-Policy`**, **clickjacking**
(`X-Frame-Options`/CSP), enforced **CSP** (`--allow-report-only-csp` to accept Report-Only mid-rollout),
**version-banner disclosure**, **cookie flags** (Secure+HttpOnly+SameSite) + **`__Host-` prefix**,
**`security.txt`** (RFC 9116), **dangerous CORS reflection** (with `--cors-path`: fails only on
reflect-arbitrary-origin **+** `Allow-Credentials: true` — a bare `*` without credentials is fine),
**TLS cert expiry**, **open redirect** (common `?next=`/`?redirect=` params), **Subresource Integrity**
on cross-origin `<script>`/`<link>`, and **rate limiting** (opt-in via `--rate-limit-path`).

### 🔎 `seo` — will Google show it right?
`<title>`, meta description, Open Graph, canonical, exactly one `<h1>`, `robots.txt`, `sitemap.xml`.

### ♿ `a11y` — basic accessibility
`<html lang>`, viewport meta, images missing `alt`, form inputs without labels.

### ⚡ `performance`
gzip/brotli compression, oversized HTML, script count, long-lived cache headers on static assets.

### White-box helpers (import into your own test suite)
| Helper | What it checks |
|---|---|
| **`idorProbe(attacker, cases)`** | Cross-tenant / **IDOR**: authenticates as tenant B and tries to reach tenant A's resources; each case must be **denied** (401/403/404). A 2xx to the attacker is reported as a cross-tenant leak. |
| **`checkSecurityHeaders(headers, {requireEnforcedCsp?})`** | Returns problems for missing/weak **HSTS**, **`nosniff`**, **`Referrer-Policy`**, and **CSP** (enforced, or Report-Only when not required). |
| **`checkCookieFlags(setCookie)`** | Returns problems if a cookie lacks **`Secure`**, **`HttpOnly`**, or **`SameSite`**. |
| **`scanSecrets(text)`** | Returns redacted hits for any hardcoded secret in a string/blob (the engine the `secrets` category uses). |

### `audit` — dependency vulnerabilities (white-box, runs in the repo)
Wraps `npm audit --json` and gates CI on severity:
```bash
anal-probe audit --level high          # fail on any high/critical advisory (default)
anal-probe audit --prod --level moderate --json
```

> Roadmap (PRs welcome): **SARIF output** (findings in GitHub's Security tab), **baseline/diff mode**
> (fail only on *new* findings), a **CSP linter** (flag `unsafe-inline`/`unsafe-eval`/wildcards),
> deeper **TLS** (protocol/cipher grading, HSTS-preload eligibility), **DNS/email hygiene**
> (SPF/DMARC, dangling-CNAME takeover), and an **authenticated crawl** beyond the entry bundle.

## Use it in CI across all repos (recommended)
```yaml
# .github/workflows/security.yml in ANY repo
name: security
on: [pull_request, workflow_dispatch]
jobs:
  probe:
    uses: newsengine/anal-probe/.github/workflows/probe.yml@main
    with:
      url: https://your-deploy.example.com
      cors_path: /api/public/health        # optional
      rate_limit_path: /api/public/health  # optional — burst-test for a 429
      fail_on: high                         # high | medium | any
      allow_report_only_csp: true           # while CSP is still Report-Only
```

> **Private repo?** `uses:` a reusable workflow from a private repo needs org "Actions access" enabled.
> The portable pattern that always works is **checkout-with-token + run the committed `dist/`** (this
> repo commits its build, so there's no build step). One-time: add a fine-grained PAT with
> **Contents: Read** on `newsengine/anal-probe` as an **org secret** named `ANALPROBE_TOKEN`:
> ```yaml
>   steps:
>     - uses: actions/checkout@v4
>       with: { repository: newsengine/anal-probe, token: '${{ secrets.ANALPROBE_TOKEN }}', path: .kit }
>     - run: node .kit/dist/cli.js https://your-deploy.example.com --fail-on high
> ```

## Use the CLI locally / ad-hoc
```bash
# full scan (all 7 categories)
npx github:newsengine/anal-probe https://app.example.com

# scope it, gate harder, test CORS, machine-readable output
npx github:newsengine/anal-probe https://app.example.com \
  --only secrets,exposure,security \
  --cors-path /api/public/health --allow-report-only-csp \
  --fail-on medium --json
```
Flags: `--only <cats>` · `--skip <cats>` · `--cors-path <p>` · `--rate-limit-path <p>` · `--allow-report-only-csp`
· `--max-crawl <n>` (links/scripts to fetch-check, default 25) · `--fail-on high|medium|any` · `--json`.

## Use the white-box helpers in your tests
```ts
import { idorProbe, checkSecurityHeaders } from '@newsengine/anal-probe';

// Cross-tenant: authenticate as tenant B, try to read tenant A's resources — must be denied.
const results = await idorProbe(tenantB, [
  { name: 'GET /api/forms/:A_id', request: () => ({ url: `${BASE}/api/internal/forms/${A_FORM_ID}` }) },
]);
for (const r of results) expect(r.ok, r.detail).toBe(true);

// Headers on a response:
expect(checkSecurityHeaders(res.headers, { requireEnforcedCsp: true })).toEqual([]);
```

## Develop
```bash
npm install && npm run build && npm test
```

## What "fail_on" means
- `high` (default): fail CI only on HIGH findings (leaked secret, exposed `.env`/`.git`, missing HSTS/CSP, non-HTTPS, dangerous CORS).
- `medium`: also fail on MEDIUM (nosniff, frame-options, cookie flags, broken links, mixed content, missing `lang`/viewport, exposed source maps, GraphQL introspection).
- `any`: fail on anything not passing (includes SEO/perf nits).

`--allow-report-only-csp` treats a `Content-Security-Policy-Report-Only` header as an acceptable
(info-level) CSP, for apps mid-rollout. Drop it once you enforce CSP.
