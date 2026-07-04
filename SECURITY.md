# Security Policy

## Reporting a vulnerability in anal-probe itself

anal-probe is a security tool, so we take issues in the tool seriously. If you find a
vulnerability **in anal-probe** (e.g. a way to make it exfiltrate data, a command-injection in
how it handles a target URL, an SSRF via a redirect, or a way its output leaks secrets it scanned):

- **Do not** open a public issue.
- Use **GitHub → Security → "Report a vulnerability"** (private advisory) on this repository, or
  email the maintainers at the address in the repo profile.
- Include a proof-of-concept and the version (`anal-probe --version`).

We aim to acknowledge within **72 hours** and to ship a fix or mitigation for confirmed issues
promptly. We'll credit you in the release notes unless you prefer to stay anonymous.

## Reporting a vulnerability you found in *your own* site with anal-probe

anal-probe reports findings on the target you scan. Those belong to **you and the site's owner** —
please report them through that project's own disclosure process, not here.

## Supported versions

Only the latest published version is supported. Please upgrade before reporting.

## Scope & safe harbor

This policy covers the anal-probe codebase. It does **not** authorize testing against any
third-party infrastructure. See [`DISCLAIMER`](README.md#-authorized-use-only) — you are
responsible for having permission to scan any target.
