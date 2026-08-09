#!/usr/bin/env bash
# Securely set STRIPE_SECRET_KEY in .env, .dev.vars, and Cloudflare Worker.
# Usage: ./scripts/set-stripe-secret.sh
# Does not print the secret.
set -euo pipefail
cd "$(dirname "$0")/.."

EXPECTED_ACCOUNT="${STRIPE_EXPECTED_ACCOUNT:-acct_1SW2BE2Aw6uDXs2h}"

echo "Paste the new Stripe SECRET key (sk_live_… or sk_test_…), then Enter."
echo "(Input is hidden — nothing is echoed.)"
read -r -s SK
echo
if [[ -z "${SK}" ]]; then
  echo "Empty key — aborted." >&2
  exit 1
fi
if [[ ! "$SK" =~ ^sk_(live|test)_ ]]; then
  echo "Key should start with sk_live_ or sk_test_ — aborted." >&2
  exit 1
fi

echo "Verifying with Stripe API…"
ACCT_JSON=$(curl -sS https://api.stripe.com/v1/account -u "${SK}:")
ACCT_ID=$(printf '%s' "$ACCT_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("id") or ""); print(d.get("error",{}).get("message",""), file=sys.stderr)' 2>/tmp/vta_stripe_err.txt || true)
if [[ -z "$ACCT_ID" ]]; then
  echo "Stripe rejected the key:" >&2
  cat /tmp/vta_stripe_err.txt >&2 || true
  printf '%s\n' "$ACCT_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("error",d), file=sys.stderr)' 2>&1 | head -5
  exit 1
fi
echo "Account: $ACCT_ID"
if [[ -n "$EXPECTED_ACCOUNT" && "$ACCT_ID" != "$EXPECTED_ACCOUNT" ]]; then
  echo "WARNING: expected $EXPECTED_ACCOUNT but key is for $ACCT_ID" >&2
  read -r -p "Continue anyway? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || exit 1
fi

update_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "STRIPE_SECRET_KEY=${SK}" >"$file"
    echo "created $file"
    return
  fi
  python3 - "$file" "$SK" <<'PY'
import sys
from pathlib import Path
path, sk = Path(sys.argv[1]), sys.argv[2]
lines = path.read_text().splitlines() if path.exists() else []
out, seen = [], False
for line in lines:
    if line.startswith("STRIPE_SECRET_KEY="):
        out.append(f"STRIPE_SECRET_KEY={sk}")
        seen = True
    else:
        out.append(line)
if not seen:
    out.append(f"STRIPE_SECRET_KEY={sk}")
path.write_text("\n".join(out) + "\n")
print(f"updated {path}")
PY
}

update_file .env
update_file .dev.vars

echo "Uploading to Cloudflare Worker (vibetesting-agent)…"
printf '%s' "$SK" | npx wrangler secret put STRIPE_SECRET_KEY

# Clear local var
unset SK
echo "Done. Secret is set locally and on the Worker. Redeploy not required for secrets."
echo "Next: open https://vibetestingagent.com/dashboard/billing and try checkout."
echo "Then delete the old sk_live_ key in the Stripe Dashboard if still listed."
