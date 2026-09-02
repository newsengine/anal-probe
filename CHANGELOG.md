# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`appstyle` category — app-type-aware rules for the top 20 business archetypes:** the scanner now
  fingerprints *what kind of app* it is from the homepage (e-commerce, SaaS dashboard, marketing site,
  blog/CMS, auth portal, headless API, marketplace, booking, fintech, healthcare, social/community,
  chat, file-sharing, admin panel, docs site, job board, real estate, LMS, CRM, helpdesk) and runs that
  type's extra rules — a store is checked for a card-skimmer CSP + payment HSTS + pinned third-party
  scripts, an auth portal for HTTPS + no-cache + a secure login form, fintech/healthcare for HSTS +
  no-store, and so on. Rules run **only** for a confidently-detected type (top match, or another type
  backed by a strong distinctive signal), mirroring the framework-detection discipline so a store's
  "Careers" link never gets job-board page rules. Detection is homepage-only (no extra requests); every
  rule is listed in `docs/CHECKS.md`.
- **Check catalog — a maintained list of every test (`docs/CHECKS.md`):** `src/catalog.ts` is now the
  single source of truth for every check the scanner runs. Each entry declares its id, category,
  severity, standards refs, the version it shipped in, and — so the tool is no longer a black box about
  its own coverage — how it reaches its verdict (`passive` reads the homepage only, `probe` makes extra
  safe GETs, `active` sends a crafted probe/burst/write, `authenticated` needs `--cookie/--header`,
  `white-box` needs source/tokens/two accounts). `npm run catalog` regenerates the doc, and
  `tests/catalog.test.ts` fails the build if the engine ever emits a finding id that isn't catalogued
  (new check → add its entry) or if the doc drifts. Adding/upgrading checks now keeps the list current.
- **API-surface checks (issue #24):** detections a homepage-only scan missed, all reachable black-box:
  - `api.unauth-data` (**on by default**, GET-only) — flags an `/api/*` route (built-in wordlist +
    routes discovered in the HTML) that answers `200` + a JSON data body with no auth challenge; graded
    high when the body looks like records/PII.
  - `api.cors` (**on by default**) — generalizes CORS-reflection testing to discovered API routes
    (any-origin reflection **with** credentials).
  - `api.unauth-write` (opt-in `--api-write`) — sends a benign no-op POST to write-suggestive routes and
    flags any `2xx`; destructive-sounding verbs are never touched and SPA HTML shells are ignored.
  - `api.rate-limit` (opt-in `--rate-limit-scan`) — autonomously bursts discovered expensive endpoints
    (`ai`, `search`, `export`, …) and expects a `429`; high on compute/LLM paths (budget-DoS).
  - `xss.reflected` (opt-in `--xss`) — injects an inert, non-executing marker into public query params
    and flags unencoded reflection (reflected XSS / HTML injection).
  - `cookie-secure.<name>` — the missing-`Secure`-flag check is now split into its own always-on finding,
    with a `getSetCookie()` fallback that parses the raw header on older runtimes so it never no-ops.
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
