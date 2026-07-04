# Contributing to anal-probe

Thanks for helping make anal-probe better. It's a **zero-dependency, black-box** web scanner, and a
few principles keep it that way.

## Ground rules

1. **Zero runtime dependencies.** Core checks must run on Node's stdlib only. The single optional
   dependency is `playwright-core`, used *only* by the opt-in browser modes (`browse`/`crawl`).
   Don't add npm dependencies to core.
2. **Low false positives.** Every finding must be **signature-validated** — don't flag on a bare
   status code. Validate the response body/headers so an SPA catch-all or a CDN error page can't
   trip it. A false positive is worse than a missed finding for this tool's audience.
3. **Non-destructive by default.** The default scan is read-only (GETs + one benign header probe).
   Anything active (port scan, fuzzing, bursts) belongs behind an explicit opt-in flag and, where
   it touches a third party, an authorization gate (see `recon --yes-i-am-authorized`).
4. **Every failing finding ships a one-line `fix`.** The audience is non-experts; tell them what to do.
5. **Map to a standard.** New checks should add an entry to `src/compliance.ts` (OWASP/ASVS/CWE/WSTG)
   so they show up in `--compliance` and the report.

## Adding a check

- Put it in the right category module (`src/checks.ts`, or a focused module like `src/components.ts`).
- Use a stable `id` (`<category>.<name>`) — ids are used by baselines and SARIF, so don't rename casually.
- Add a unit test to `tests/probe.test.ts` (we use Node's built-in `node:test`, importing the built
  `dist/` so we test exactly what ships).

## Dev loop

```bash
npm install          # dev only (typescript + playwright-core)
npm run build        # tsc -> dist/ (dist IS committed; rebuild before you commit)
npm test             # builds, then runs the full node:test suite
```

Please run `npm test` and commit the regenerated `dist/` with your source change.

## Keeping the vuln data fresh

`src/components.ts` carries a curated known-vulnerable-library table. If you bump it, cite the
CVE/advisory in the entry's `ref`. (A maintained auto-updating feed is on the roadmap — PRs welcome.)

## Pull requests

- One logical change per PR; describe *what* and *why*.
- Green CI (build + tests) is required.
- By contributing you agree your work is licensed under the project's Apache-2.0 license.
