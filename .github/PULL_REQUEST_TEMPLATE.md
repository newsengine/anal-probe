<!-- Thanks for contributing! Keep PRs to one logical change. -->

## What & why

<!-- What does this change, and what problem does it solve? -->

## Checklist

- [ ] `npm test` passes (build + full `node:test` suite)
- [ ] Regenerated `dist/` is committed alongside the source change
- [ ] New checks are **signature-validated** (won't false-positive on a catch-all / CDN page)
- [ ] New failing findings include a one-line `fix`
- [ ] New checks add a mapping in `src/compliance.ts` (OWASP/ASVS/CWE/WSTG)
- [ ] No new runtime npm dependencies in core
- [ ] Anything active (scanning/fuzzing) is opt-in and, if it touches third parties, authorization-gated
- [ ] No secrets or personal/private data added to code, tests, or fixtures
