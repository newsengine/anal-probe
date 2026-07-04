# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`plugins` category — custom JSON check templates:** point `--plugins <dir>` at a folder of JSON
  templates (request + status/header/body matchers with and/or conditions, invertible via `negative`)
  and they run as first-class findings — no code, no fork. Malformed templates are skipped (never fatal);
  GET/HEAD-only and a template cap keep it safe. Schema + examples in `plugins/`.
- **Auto-updating vulnerability feed** for `components`: `npm run update-vuln-db` refreshes the
  known-vulnerable-library table from the retire.js community feed (union-merged with the curated seed,
  currently 12 libraries / 200+ ranges), so it doesn't go stale. Table now lives in `src/vuln-data.ts`.
- **CSRF-protection heuristic** (in `security`): state-changing POST forms lacking an anti-CSRF token,
  SameSite-cookie-aware so it only flags genuinely-unprotected forms (CWE-352 / A01).
- **DOM-XSS** heuristic (in `security`): a URL/`referrer`/`window.name` source flowing directly into an
  `innerHTML`/`document.write`/`eval`/`insertAdjacentHTML` sink in inline script (CWE-79 / A03).
- **`components` category (OWASP A06 — Vulnerable & Outdated Components):** retire.js-style detection
  of vulnerable/outdated client-side JS libraries (jQuery, jQuery UI, Bootstrap, Lodash, AngularJS,
  Handlebars, Moment, axios, DOMPurify, Vue 2, Underscore, Select2), matched against a curated
  known-vulnerable version table. Detects current versions too (no false positives).
- **JWT hygiene** (in `security`): decodes (does not verify) any browser-exposed JWT and flags
  `alg:none`, missing `exp`, over-long lifetime, and non-HttpOnly-cookie storage.
- **Host-header injection** probe (in `security`): flags a spoofed `X-Forwarded-Host` reflected into
  redirects/URLs (password-reset-link / web-cache poisoning).
- **CSRF-protection heuristic** (in `security`): state-changing POST forms lacking an anti-CSRF token,
  SameSite-cookie-aware so it only flags genuinely-unprotected forms (CWE-352 / A01).
- **DOM-XSS** heuristic (in `security`): a URL/`referrer`/`window.name` source flowing directly into an
  `innerHTML`/`document.write`/`eval`/`insertAdjacentHTML` sink in inline script (CWE-79 / A03).
- **Render-health** checks (`browse`/`crawl`): detects rendered error boundaries, framework crash
  overlays, and blank app roots — client-side failures that return HTTP 200 with no console error.
- Open-source release scaffolding: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, issue/PR templates, and an "authorized use only" disclaimer.

### Changed
- Compliance mapping extended for the new checks (A06/CWE-1104; A02/CWE-347 for `alg:none`;
  A03/CWE-644 for host-header).

## [0.6.0]

Baseline for the changelog. Prior work: 11-category black-box scan (security/secrets/exposure/dns/
reliability/seo/a11y/performance/agent/framework/host), OWASP ASVS L1 / Top 10 / WSTG / CWE mapping,
HTML/PDF report, SARIF + baseline output, opt-in `recon`/`browse`/`crawl`/`separation`/`cve` modes,
and importable white-box helpers (IDOR/RBAC/mass-assignment/data-isolation).
