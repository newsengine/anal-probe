# Architecture — who does what

## Decision

| Role | Machine | Why |
|---|---|---|
| **UI, auth, billing, lite scan, job queue** | Cloudflare Workers | Global edge, D1, WorkOS, Stripe |
| **Full vibetesting-agent scans** | **OVH `jclaw1`** (`51.81.109.145` / Tailscale `100.88.32.128`) | Node 22, Docker, RAM/disk; runs real suite |
| **ovh-ca-db** | Not used for scans | SSH key denied; leave as DB/other |

## Flow

```text
User → Workers (lite free CTA runs immediately)
User → paid/full scan → D1 status=queued
jclaw1 agent polls POST /api/v1/agent/claim
jclaw1 runs: node /opt/vta/vibetesting-agent/dist/cli.js <url> --json
jclaw1 posts POST /api/v1/agent/complete
Dashboard shows full results
```

## jclaw1 service

```bash
ssh jclaw1
sudo systemctl status vta-scan-agent
journalctl -u vta-scan-agent -f
```

Files: `/opt/vta/ovh-scan-agent.mjs`, `/opt/vta/agent.env`, `/opt/vta/vibetesting-agent/`

## Secrets

- Worker + agent share `SCAN_AGENT_SECRET`
- Agent never needs WorkOS/Stripe keys
