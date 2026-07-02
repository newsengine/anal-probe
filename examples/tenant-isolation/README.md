# Tenant-isolation (separation-of-accounts) test

Proves that account **B cannot read account A's data** in a multi-tenant app that scopes data by a
tenant/org id in the query string (e.g. `?tenant_uuid=…`). The classic bug is a backend that trusts that
parameter instead of checking the caller belongs to the tenant.

It reuses **two of your existing Chrome profiles** (already signed in) so there are **no passwords** to
handle. It launches an isolated Chrome seeded with each profile's cookies, lets the app fire its own
authenticated requests, and for the attacker **rewrites the tenant id to the owner's**. Then it grades
each endpoint with the shipped `classifyTenantAccess` logic (unit-tested in the main suite).

**Strictly read-only:** only `GET`s are observed and rewritten. It never issues a write and never mutates
another tenant.

## Use

```bash
npm i -D playwright-core        # uses your installed Google Chrome; no browser download
cp examples/tenant-isolation/config.example.json examples/tenant-isolation/config.json
# edit config.json: your two Chrome profile dirs, the two tenant ids, and the endpoints to test
npm run build                  # the harness imports dist/testkit.js

# IMPORTANT: open the app in BOTH Chrome profiles first so their sessions/tokens are fresh
node examples/tenant-isolation/run.mjs examples/tenant-isolation/config.json
```

Find your profile → account mapping with:

```bash
for d in "$HOME/Library/Application Support/Google/Chrome"/Profile*; do
  echo "$(basename "$d") => $(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('account_info',[{}])[0].get('email','?'))" "$d/Preferences")"
done
```

Get the tenant ids from the app itself (e.g. the `tenant_uuid` in its API requests, or `/api/auth/session`).

## Reading the result

| Verdict | Meaning |
|---|---|
| `isolated` | attacker was denied (401/403/404) or got no owner data — good |
| `leak` | attacker received the owner's actual data — **real bug** |
| `inspect` | 200 with data that is neither the owner's nor the attacker's own — review by hand |
| `inconclusive` | no valid baseline (a legitimate request didn't return 200) — sessions are stale; refresh & retry |

`inconclusive` is important: a `401` on the attack means nothing if the *legitimate* request also 401s
(a dead token), so the harness refuses to call that a pass.

## Notes / limits
- macOS paths are the default; set `CHROME_BIN` and `chromeProfilesDir` for Linux/Windows.
- Chrome decrypts the copied cookies via the system Keychain automatically — the script never reads the
  Keychain itself.
- Repeated launches can consume rotating refresh tokens; keep runs minimal and refresh sessions between.
- This tests the read side. To reason about writes safely, verify read-isolation first — a shared authz
  layer that blocks cross-tenant reads almost always blocks writes too — and only test writes against
  your own tenant.
- `config.json` is git-ignored (it contains your tenant ids); commit only `config.example.json`.
