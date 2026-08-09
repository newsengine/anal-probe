# Standards & compliance mapping

vibetesting-agent maps its checks to recognized standards so a scan doubles as a conformance check. Run any
scan with `--compliance` for a live report (ASVS L1 coverage, OWASP Top 10 + API Top 10, CWE list, and
A+–F security/TLS scorecards):

```bash
vibetesting-agent https://your-app.example.com --compliance          # human report
vibetesting-agent https://your-app.example.com --compliance --json    # findings tagged with standards + coverage block
```

## Standards coverage at a glance — what we DO and DON'T test

vibetesting-agent is a **safe-to-run black-box** scanner: a URL in, no source, no authentication required, no
attack payloads. That boundary decides what we can honestly test. Everything below is deliberate.

| Standard / checklist | Status | Notes |
|----------------------|--------|-------|
| **OWASP ASVS 4.0.3 — Level 1** | ✅ **23/25** black-box reqs | full table below; 2 honest gaps (V3.4.5, V14.4.2) |
| OWASP ASVS — Level 2 / 3 | ⛔ not tested | need authenticated flows, token/entropy analysis, source review |
| **OWASP Top 10 (2021)** | ✅ mapped | A01/A02/A05 strong; A06/A07/A08 partial; A03/A09/A10 out (below) |
| **OWASP API Security Top 10 (2023)** | ✅ partial | API1 BOLA, API4 resource-consumption, API5 BFLA (via testkit), API8 misconfig, API9 inventory |
| **OWASP WSTG** | ✅ per-finding IDs | information-gathering, config, error-handling, crypto, client-side test IDs |
| **CWE (MITRE)** | ✅ every finding tagged | e.g. CWE-319, CWE-1021, CWE-693; emitted in `--compliance` + SARIF (`external/cwe/*`) |
| **CVE — dependencies** | ✅ `audit` | npm/GitHub advisory database |
| **CVE — services** | ✅ `recon --cve` / `cve` | NVD keyword API for detected product+version |
| **NIST SP 800-52r2 (TLS)** | ✅ via TLS grading | protocol/cipher/HSTS map to the TLS config guidance |
| **PCI-DSS 4.0 (web subset)** | ✅ partial | Req 4 (TLS), 6.4.3 (SRI), 2.2/6.2 (config/headers) — the black-box-observable parts |
| **Mozilla Observatory / securityheaders** | ✅ A+–F header grade | `securityGrade` scorecard |
| **SSL Labs (Qualys)** | ✅ A+–F TLS grade | `tlsGrade` scorecard (protocol/cipher/HSTS/redirect) |
| **WCAG 2.2 (accessibility)** | ⚠️ basic | `a11y` category maps to SC 1.1.1 (alt), 3.1.1 (lang), 1.4.10 (viewport), 1.3.1 (labels) — not a full audit |
| OWASP Top 10 **A03 Injection** | ⛔ not tested | needs active SQLi/XSS fuzzing — not safe to run against production |
| OWASP Top 10 **A10 SSRF** | ⛔ not tested | needs active exploitation |
| OWASP Top 10 **A09 Logging/Monitoring** | ⛔ not testable | server-side, not observable over HTTP |
| CSRF (active) | ⛔ not tested | needs an authenticated flow + crafted requests (we do check SameSite) |
| File-upload validation (ASVS V12) | ⛔ not tested | needs an authenticated upload + active payloads |
| **CIS Benchmarks** (server/OS) | ⛔ out of scope | host-config hardening, needs system access not black-box |
| **ISO 27001 / SOC 2 / HIPAA / GDPR** | ⛔ out of scope | organizational/process frameworks — a scanner provides *evidence*, can't certify them |
| **OWASP MASVS/MASTG** (mobile), **SAMM** | ⛔ n/a | mobile / maturity-model, not web-app-scan applicable |
| **OWASP Top 10 2025** | ⏳ tracking | not finalized as of this writing; will map when released |

**The rule:** we test everything verifiable black-box without sending attack payloads or needing an
account. The ⛔ items require active exploitation, authenticated flows, source review, or system access —
that's ZAP / Burp / manual-pentest / SCA-at-build-time territory, and claiming to "test" them would be
dishonest. For those, vibetesting-agent tells you where its coverage ends.

## OWASP ASVS 4.0.3 — Level 1, black-box-testable subset

ASVS L1 has 25 requirements that are verifiable purely black-box (no source, no auth, no active
exploitation). vibetesting-agent covers **23 of 25**; the two gaps are noted honestly.

| ASVS | Requirement | vibetesting-agent check |
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
