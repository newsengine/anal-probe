# DNS email & CA hardening (SPF / DMARC / CAA)

vibetesting-agent flags these when missing. The deploy token currently has **no Zone.DNS Edit** permission, so add them in the [Cloudflare dashboard](https://dash.cloudflare.com) for zone `vibetestingagent.com`, or mint a token with **Zone → DNS → Edit** and re-run:

```bash
ZONE_ID=777bc52b38dc71ffb4def93cd58ed92b
TOKEN=... # Zone DNS Edit

# SPF — domain does not send mail; hard-fail all senders
curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data '{"type":"TXT","name":"vibetestingagent.com","content":"v=spf1 -all","ttl":3600}'

# DMARC — reject spoofed mail
curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data '{"type":"TXT","name":"_dmarc","content":"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s","ttl":3600}'

# CAA — only Let's Encrypt / Google Trust Services (Cloudflare Universal SSL)
curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data '{"type":"CAA","name":"vibetestingagent.com","data":{"flags":0,"tag":"issue","value":"letsencrypt.org"},"ttl":3600}'
curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data '{"type":"CAA","name":"vibetestingagent.com","data":{"flags":0,"tag":"issue","value":"pki.goog; cansignhttpexchs=yes"},"ttl":3600}'
```

Dashboard equivalents:

| Type | Name | Content |
|------|------|---------|
| TXT | `@` | `v=spf1 -all` |
| TXT | `_dmarc` | `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s` |
| CAA | `@` | `0 issue "letsencrypt.org"` |
| CAA | `@` | `0 issue "pki.goog; cansignhttpexchs=yes"` |

If you later send transactional mail (Cloudflare Email Routing / Resend / SES), replace SPF with the provider's `include:` and loosen DMARC to `p=quarantine` while monitoring.
