# Open-sourcing VibeTesting Agent / vibetesting-agent

## What is open source

| Package | License | Repo |
|---|---|---|
| **vibetesting-agent** (scanner engine, CLI, Gherkin/agent-report, CI helpers) | Apache-2.0 | https://github.com/newsengine/vibetesting-agent |
| **vibetesting-agent** (docs, branding, OSS entry README) | Apache-2.0 | https://github.com/newsengine/vibetesting-agent |

## What stays hosted / commercial

- Multi-tenant dashboard on **vibetestingagent.com**
- WorkOS authentication
- Stripe subscriptions ($25 / $100 / $250)
- Ownership verification orchestration, rate limits, audit storage as a service
- Deploy/commit webhook SaaS queue

The hosted app under `vibetesting-agent/` may be dual-licensed later; today treat production billing secrets and customer data as private.

## Pre-release checklist

- [x] Apache-2.0 LICENSE on scanner
- [x] SECURITY.md, CODE_OF_CONDUCT, CONTRIBUTING
- [x] Authorized-use warnings in CLI + docs
- [x] No customer PII in repo
- [x] `npx github:newsengine/vibetesting-agent` zero-install path
- [x] Agent report + Gherkin + `review` / `init` subcommands
- [ ] Ensure GitHub repo visibility is **public**
- [ ] Tag a release (e.g. `v0.7.0`)
- [ ] GitHub Pages for `docs/index.html` (optional)

## Publish steps

```bash
# From vibetesting-agent
npm test
npm run build
gh repo edit newsengine/vibetesting-agent --visibility public   # if still private
gh release create v0.7.0 --generate-notes

# Brand entry repo
gh repo create newsengine/vibetesting-agent --public --description "VibeTesting Agent — security for vibe-coded apps" --source=./oss-entry --push
```

## Community message

> VibeTesting Agent is the hosted product. **vibetesting-agent** is the free forever CLI and library.
> Point it at deploys you own. Use `/security-review` for agent fix packs.
