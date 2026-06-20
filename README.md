# @newsengine/anal-probe

Reusable security checks for our SaaS apps — drop into **any** repo.

- **Black-box probe** (`security-kit probe <url>`): security headers, HTTP→HTTPS, `security.txt`
  (RFC 9116), cookie flags, version-banner disclosure, and dangerous CORS reflection. Exits non-zero
  on failures → gates CI. No source access needed, so it works against every deploy identically.
- **White-box helpers** (`idorProbe`, `checkSecurityHeaders`, `checkCookieFlags`): import into your own
  test suite (jest/vitest/node:test) for cross-tenant/IDOR + header/cookie assertions.
- **Templates**: `SECURITY.md`, `security.txt`, `CODEOWNERS`.
- **Reusable GitHub Actions workflow**: `.github/workflows/probe.yml` (call it with `uses:`).

## Security checks performed

### Black-box probe (`security-kit probe <url>` / the CI workflow)
Runs against a deployed URL — no source access — so every deploy is checked identically.

| # | Check (finding id) | Severity | What it verifies / fails on |
|---|---|---|---|
| 1 | **HTTPS scheme** (`tls.scheme`) | high | The base URL is served over `https:`, not `http:`. |
| 2 | **HTTP→HTTPS redirect** (`tls.redirect`) | medium | Hitting the `http://` origin returns a 3xx redirect to `https://`. |
| 3 | **Reachability** (`reachability`) | high | The site responds at all (fails closed if unreachable). |
| 4 | **HSTS** (`header.strict-transport-security`) | high | `Strict-Transport-Security` present with a long `max-age` (≥ 5 digits). |
| 5 | **MIME sniffing** (`header.x-content-type-options`) | medium | `X-Content-Type-Options: nosniff` is set. |
| 6 | **Referrer policy** (`header.referrer-policy`) | low | `Referrer-Policy` is set. |
| 7 | **Clickjacking** (`header.x-frame-options`) | medium | `X-Frame-Options` (or a CSP `frame-ancestors`) is set. |
| 8 | **Content-Security-Policy** (`header.content-security-policy`) | high | An enforced `Content-Security-Policy` is set. With `--allow-report-only-csp`, a `Content-Security-Policy-Report-Only` header counts as **info** (not a fail) for apps mid-rollout. |
| 9 | **Server banner disclosure** (`disclosure.server`) | low | The `Server` header does **not** leak a version number. |
| 10 | **Powered-by disclosure** (`disclosure.x-powered-by`) | low | The `X-Powered-By` header does **not** leak a version/stack. |
| 11 | **Cookie flags** (`cookie.<name>`) | medium | Every `Set-Cookie` carries `Secure` + `HttpOnly` + `SameSite` (one finding per cookie). |
| 12 | **security.txt** (`securitytxt`) | low | `/.well-known/security.txt` exists and has the RFC 9116 required `Contact` + `Expires` fields. |
| 13 | **Dangerous CORS reflection** (`cors.reflection`) | high | With `--cors-path`, sends `Origin: https://evil.example`; **fails** only if the server reflects that arbitrary origin **and** sets `Access-Control-Allow-Credentials: true` (the exploitable combo). A bare wildcard `*` without credentials is treated as info/OK for public endpoints. |
| 14 | **TLS cert expiry** (`tls.expiry`) | high&lt;14d / med&lt;30d | Reads the served certificate and fails when it expires in &lt; 14 days (medium under 30). |
| 15 | **Sensitive file exposure** (`exposure/...`) | high | `/.git/HEAD`, `/.git/config`, `/.env`, `/.env.local`, `/.env.production`, `/.DS_Store` must not be publicly readable. Only flags when the body matches the file's signature (a SPA's 200+index.html fallback is not a false positive). |
| 16 | **Mixed content** (`mixed-content`) | medium | On an HTTPS page, no `http://` resources are referenced in the HTML. |
| 17 | **Source-map exposure** (`sourcemaps`) | low | The page's main bundles don't serve an adjacent `.js.map` (which leaks original source). |
| 18 | **Open redirect** (`open-redirect`) | high | Common redirect params (`next`, `redirect`, `redirect_uri`, `url`, `return`, `returnTo`, `dest`, `continue`) don't 3xx to an off-domain attacker URL. |
| 19 | **Rate limiting** (`rate-limit`) | medium | *Opt-in* (`--rate-limit-path`): a 25-request burst to the path is throttled (429). |
| 20 | **Subresource Integrity** (`sri`) | low | Cross-origin `<script>`/`<link rel=stylesheet>` carry an `integrity` attribute. |
| 21 | **Cookie prefix** (`cookie-prefix.<name>`) | info | Recommends a `__Host-`/`__Secure-` prefix on session cookies. |

### Dependency audit (`security-kit audit`)
Runs `npm audit` in the current repo and gates on severity:
```bash
security-kit audit --level high     # fail on any high/critical advisory (default)
security-kit audit --prod --level moderate --json
```

### White-box helpers (import into your own test suite)
| Helper | What it checks |
|---|---|
| **`idorProbe(attacker, cases)`** | Cross-tenant / **IDOR**: authenticates as tenant B and tries to reach tenant A's resources; each case must be **denied** (401/403/404). A 2xx to the attacker is reported as a cross-tenant leak. |
| **`checkSecurityHeaders(headers, {requireEnforcedCsp?})`** | Returns problems for missing/weak **HSTS**, **`nosniff`**, **`Referrer-Policy`**, and **CSP** (enforced, or Report-Only when not required). |
| **`checkCookieFlags(setCookie)`** | Returns problems if a cookie lacks **`Secure`**, **`HttpOnly`**, or **`SameSite`**. |

> Roadmap: all listed checks are implemented. Future ideas (PRs welcome): TLS protocol/cipher grading, CSP directive linting, and an authenticated-crawl mode.

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
      fail_on: high                         # high | medium | any
      allow_report_only_csp: true           # while CSP is still Report-Only
```

## Use the CLI locally / ad-hoc
```bash
npx github:newsengine/anal-probe https://app.example.com \
  --rate-limit-path /api/public/health \
  --cors-path /api/public/health --allow-report-only-csp --fail-on high
# add --json for machine-readable output
```

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
- `high` (default): fail CI only on HIGH findings (missing HSTS/CSP, non-HTTPS, dangerous CORS).
- `medium`: also fail on MEDIUM (nosniff, frame-options, cookie flags).
- `any`: fail on anything not passing.

`--allow-report-only-csp` treats a `Content-Security-Policy-Report-Only` header as an acceptable
(info-level) CSP, for apps mid-rollout. Drop it once you enforce CSP.
