# VibeTesting Agent

**https://vibetestingagent.com**

Security scanning for **vibe-coded** apps — continuous ship checks, agent fix packs, ownership-gated hosted scans.

## Open-source scanner

The engine is **[vibetesting-agent](https://github.com/newsengine/vibetesting-agent)** (Apache-2.0):

```bash
# Full black-box scan
npx github:newsengine/vibetesting-agent https://your-app.example.com

# Security review → agent markdown + Gherkin
npx github:newsengine/vibetesting-agent review https://your-app.example.com

# Scaffold suite into a new repo
npx github:newsengine/vibetesting-agent init https://your-app.example.com --name my-app
```

### What it checks

Secrets · exposed config · security headers / TLS / CORS · DNS (SPF/DMARC/CAA) · framework misconfigs · vulnerable client libraries · reliability · SEO · a11y · performance · agent readiness · host intel · custom JSON plugins.

Plus white-box helpers: IDOR, RBAC, tenant isolation, mass assignment.

## Hosted product

| Plan | Price | Cadence |
|---|---|---|
| Lite | Free | Public homepage lite scan |
| Weekly | $25/mo | 1 full scan / week |
| Daily | $100/mo | Daily scans + deploy hooks |
| Every commit | $250/mo | Scan on every push |

Paid plans **require domain ownership verification** so you cannot scan apps that are not yours.

Sign up: https://vibetestingagent.com

## License

Documentation and this meta-repo: Apache-2.0.  
Scanner: Apache-2.0 under [newsengine/vibetesting-agent](https://github.com/newsengine/vibetesting-agent).

## Authorized use only

Only test systems you own or have explicit written permission to test.
