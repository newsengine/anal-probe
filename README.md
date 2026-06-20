# @newsengine/anal-probe

Reusable security checks for our SaaS apps — drop into **any** repo.

- **Black-box probe** (`security-kit probe <url>`): security headers, HTTP→HTTPS, `security.txt`
  (RFC 9116), cookie flags, version-banner disclosure, and dangerous CORS reflection. Exits non-zero
  on failures → gates CI. No source access needed, so it works against every deploy identically.
- **White-box helpers** (`idorProbe`, `checkSecurityHeaders`, `checkCookieFlags`): import into your own
  test suite (jest/vitest/node:test) for cross-tenant/IDOR + header/cookie assertions.
- **Templates**: `SECURITY.md`, `security.txt`, `CODEOWNERS`.
- **Reusable GitHub Actions workflow**: `.github/workflows/probe.yml` (call it with `uses:`).

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
npx github:newsengine/anal-probe security-kit https://app.example.com \
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
