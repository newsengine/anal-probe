#!/usr/bin/env bash
# Harden jclaw1: deny inbound from internet; allow Tailscale + established.
# Safe defaults for a scan-only node that only needs outbound HTTPS + SSH via Tailscale.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run with sudo"
  exit 1
fi

# Ensure ufw
if ! command -v ufw >/dev/null; then
  apt-get update -qq && apt-get install -y -qq ufw
fi

# Tailscale interface
TS_IF="${TAILSCALE_IFACE:-tailscale0}"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH only on Tailscale (not public 0.0.0.0/0)
if ip link show "$TS_IF" >/dev/null 2>&1; then
  ufw allow in on "$TS_IF" to any port 22 proto tcp comment 'SSH via Tailscale only'
  ufw allow in on "$TS_IF" comment 'Tailscale mesh'
else
  echo "WARN: $TS_IF not found — allowing SSH from anywhere temporarily is DANGEROUS"
  echo "Install/start tailscale first, or re-run this script after."
  # Still lock down: only rate-limited SSH from anywhere as last resort for recovery
  ufw limit 22/tcp comment 'SSH rate-limited fallback'
fi

# No public HTTP/scan ports
ufw deny 80/tcp
ufw deny 443/tcp
ufw deny 3000/tcp
ufw deny 8080/tcp

ufw --force enable
ufw status verbose

echo "Done. jclaw1 should only accept admin via Tailscale; scan agent uses outbound HTTPS only."
