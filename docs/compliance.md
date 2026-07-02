# Standards & compliance mapping

anal-probe maps its checks to recognized standards so a scan doubles as a conformance check. Run any
scan with `--compliance` for a live report:

```bash
anal-probe https://your-app.example.com --compliance          # ASVS L1 + OWASP Top 10 report
anal-probe https://your-app.example.com --compliance --json    # machine-readable (findings tagged + coverage)
```

Standards covered: **OWASP ASVS 4.0.3**, **OWASP Top 10 (2021)**, **OWASP WSTG**. Dependency CVEs via
`audit` (npm advisory DB); service CVEs via `recon --cve` / `cve` (NVD).

## OWASP ASVS 4.0.3 — Level 1, black-box-testable subset

ASVS L1 has 25 requirements that are verifiable purely black-box (no source, no auth, no active
exploitation). anal-probe covers **23 of 25**; the two gaps are noted honestly.

| ASVS | Requirement | anal-probe check |
|------|-------------|------------------|
| V3.4.1 | Session cookies `Secure` | `cookie.*` |
| V3.4.2 | Session cookies `HttpOnly` | `cookie.*` |
| V3.4.3 | Session cookies `SameSite` | `cookie.*` |
| V3.4.4 | Session cookies `__Host-` prefix | `cookie-prefix.*` |
| V3.4.5 | Cookie `Path` scoped tightly | — *(not yet covered)* |
| V7.4.1 | Generic errors, no stack traces | `error.stacktrace` |
| V8.2.1 | Anti-caching on sensitive responses | `cache.sensitive` *(authenticated scans)* |
| V9.1.1 | TLS everywhere, no insecure fallback | `tls.scheme`, `tls.redirect` |
| V9.1.2 | Only strong cipher suites | `tls.cipher` |
| V9.1.3 | Only latest TLS versions (1.2/1.3) | `tls.protocol` |
| V12.5.1 | Backup/temp/archive files not served | `exposed/*` (.bak/.zip/.tar.gz/…) |
| V13.1.3 | URLs don't expose keys/tokens | `secret.*` |
| V14.2.2 | Sample apps/docs/default configs removed | `framework.*` |
| V14.2.3 | External assets use SRI | `sri` |
| V14.3.2 | Debug modes disabled | `debug-leak`, `framework.*.debug` |
| V14.3.3 | No version info disclosure | `disclosure.*` |
| V14.4.1 | Content-Type + safe charset | `header.content-type` |
| V14.4.2 | `Content-Disposition` on API responses | — *(not yet covered)* |
| V14.4.3 | Content-Security-Policy present | `header.content-security-policy`, `csp.*` |
| V14.4.4 | `X-Content-Type-Options: nosniff` | `header.x-content-type-options` |
| V14.4.5 | HSTS on all responses | `header.strict-transport-security`, `tls.hsts-preload` |
| V14.4.6 | `Referrer-Policy` set | `header.referrer-policy` |
| V14.4.7 | Clickjacking defense | `header.x-frame-options` |
| V14.5.1 | Only in-use HTTP methods accepted | `http.methods` |
| V14.5.3 | CORS strict allow-list (no `null`) | `cors.reflection` *(`--cors-path`)* |

**Deliberately out of ASVS L1 black-box scope** (need source review, an authenticated flow, or active
exploitation — that's ZAP/Burp/manual-pentest territory, not a safe-to-run scanner): session-token
entropy/rotation (V3.2/V3.3), injection & path-traversal (V5, V12.3), file-upload validation (V12.x),
SSRF (V12.6), server-side logging (V7.1), and anything requiring authenticated business-logic testing.

## OWASP Top 10 (2021) coverage

| | Category | Coverage |
|--|----------|----------|
| A01 | Broken Access Control | ✅ `idorProbe`/`rbacProbe`/`dataIsolationProbe`, open-redirect, CORS |
| A02 | Cryptographic Failures | ✅ TLS grading, HSTS, secrets, mixed content |
| A03 | Injection | ❌ by design (no active fuzzing) |
| A04 | Insecure Design | ➖ not black-box automatable |
| A05 | Security Misconfiguration | ✅ headers, exposure, framework, methods, CORS |
| A06 | Vulnerable Components | ⚠️ `audit` (deps) + `recon --cve` (services) |
| A07 | Auth Failures | ⚠️ rate-limit, cookie flags, auth enforcement |
| A08 | Software/Data Integrity | ⚠️ SRI, source-map exposure |
| A09 | Logging/Monitoring | ❌ not observable black-box |
| A10 | SSRF | ❌ by design (active) |

## WSTG references

Individual findings carry WSTG test IDs (e.g. `http.methods` → WSTG-CONF-06, `cors.reflection` →
WSTG-CLNT-07, `disclosure.*` → WSTG-INFO-08). Use `--compliance --json` to see per-finding `standards`.
