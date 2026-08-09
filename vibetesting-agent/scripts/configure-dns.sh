#!/usr/bin/env bash
# Configure vibetestingagent.com DNS on Cloudflare.
# Requires CLOUDFLARE_API_TOKEN with Zone.DNS Edit on the zone.
set -euo pipefail

ZONE_ID="${CF_ZONE_ID:-777bc52b38dc71ffb4def93cd58ed92b}"
TOKEN="${CLOUDFLARE_API_TOKEN:?Set CLOUDFLARE_API_TOKEN}"
# Target for the site — Cloudflare Pages project host or worker route
TARGET="${VTA_DNS_TARGET:-vibetesting-agent.pages.dev}"

api() {
  curl -sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$@"
}

echo "Zone: $ZONE_ID  target: $TARGET"

upsert() {
  local type="$1" name="$2" content="$3" proxied="${4:-true}"
  local existing
  existing=$(api "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=$type&name=$name")
  local id
  id=$(echo "$existing" | python3 -c "import sys,json; r=json.load(sys.stdin).get('result') or []; print(r[0]['id'] if r else '')")
  local body
  body=$(python3 -c "import json; print(json.dumps({'type':'$type','name':'$name','content':'$content','proxied':$proxied,'ttl':1}))")
  if [ -n "$id" ]; then
    echo "Update $type $name → $content"
    api -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$id" --data "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(' ok' if d.get('success') else d)"
  else
    echo "Create $type $name → $content"
    api -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" --data "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(' ok' if d.get('success') else d)"
  fi
}

# Apex CNAME flattening (Cloudflare supports CNAME on root when proxied)
upsert CNAME "vibetestingagent.com" "$TARGET" true
upsert CNAME "www.vibetestingagent.com" "vibetestingagent.com" true

echo "Done. Verify: dig +short vibetestingagent.com"
