#!/usr/bin/env bash
# Local smoke path — no deploy required
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
echo "→ build scanner"
npm run build
cd vibetesting-agent
echo "→ install + build app"
npm install --silent
npm run build
echo ""
echo "Ready. Start with:"
echo "  cd $ROOT/vibetesting-agent && npm run dev"
echo "  open http://localhost:3000"
echo ""
echo "Your remaining clicks: see YOU_DO_THIS.md"
