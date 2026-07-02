// run.mjs — config-driven cross-tenant (separation-of-accounts) read-isolation test.
//
//   node examples/tenant-isolation/run.mjs config.json
//
// It logs in as neither account — it reuses two of your existing Chrome profiles (already signed in),
// lets each profile's app fire its OWN authenticated requests (correct cookies + tokens + headers), and
// for the attacker rewrites the tenant id on outgoing requests to the OWNER's tenant. It then classifies
// each endpoint with the shipped testkit logic. STRICTLY READ-ONLY: only GETs are observed/rewritten;
// it never issues writes, and never mutates another tenant.
//
// A valid result requires FRESH sessions — open the app in both Chrome profiles first so tokens refresh.

import fs from 'node:fs';
import { launchProfile } from './chrome-session.mjs';
import { setTenantParam, classifyTenantAccess } from '../../dist/testkit.js';

const cfg = JSON.parse(fs.readFileSync(process.argv[2] || new URL('./config.json', import.meta.url), 'utf8'));
const matchOf = (u) => cfg.endpoints.find((e) => u.includes(e.match)) || null;

async function drive({ tag, srcProfile, port, rewriteTenant }) {
  const s = await launchProfile({ profilesDir: cfg.chromeProfilesDir, srcProfile, tag, port });
  const ctx = s.browser.contexts()[0] || (await s.browser.newContext());
  const page = await ctx.newPage();

  if (rewriteTenant) {
    await page.route('**/*', (route) => {
      const u = route.request().url();
      const e = matchOf(u);
      if (route.request().method() === 'GET' && e && u.includes(`${cfg.tenantParam}=`)) {
        return route.continue({ url: setTenantParam(u, rewriteTenant, cfg.tenantParam) });
      }
      return route.continue();
    });
  }

  const seen = new Map();
  page.on('requestfinished', async (req) => {
    if (req.method() !== 'GET') return;               // read-only: ignore writes entirely
    const e = matchOf(req.url());
    if (!e || seen.has(e.name)) return;
    try { const res = await req.response(); if (res) seen.set(e.name, { status: res.status(), body: (await res.text()).slice(0, 2000) }); } catch {}
  });

  for (const p of cfg.appPaths) {
    await page.goto(cfg.origin + p, { waitUntil: 'networkidle', timeout: 30000 }).catch(() => {});
    await page.waitForTimeout(2500);
  }
  await s.close();
  return seen;
}

console.log(`Owner   = ${cfg.owner.label} (profile "${cfg.owner.profile}", tenant ${cfg.owner.tenant})`);
console.log(`Attacker= ${cfg.attacker.label} (profile "${cfg.attacker.profile}", tenant ${cfg.attacker.tenant})\n`);

console.log('Capturing OWNER baseline…');
const baseline = await drive({ tag: 'owner', srcProfile: cfg.owner.profile, port: 9231 });
console.log('Capturing ATTACKER control…');
const control = await drive({ tag: 'attacker-ctl', srcProfile: cfg.attacker.profile, port: 9232 });
console.log('Running ATTACK (attacker requests owner tenant)…\n');
const attack = await drive({ tag: 'attacker-att', srcProfile: cfg.attacker.profile, port: 9233, rewriteTenant: cfg.owner.tenant });

let leaks = 0, inconclusive = 0;
console.log('══════════ CROSS-TENANT READ ISOLATION ══════════\n');
for (const e of cfg.endpoints) {
  const { verdict, reason } = classifyTenantAccess({ baseline: baseline.get(e.name), attack: attack.get(e.name), control: control.get(e.name) });
  if (verdict === 'leak') leaks++; if (verdict === 'inconclusive') inconclusive++;
  const icon = verdict === 'leak' ? '🟥' : verdict === 'isolated' ? '✅' : verdict === 'inspect' ? '⚠️ ' : '·';
  console.log(`${icon} ${verdict.toUpperCase().padEnd(12)} ${e.name} — ${reason}`);
}
console.log(`\n${leaks ? '🟥 ' : '✅ '}${cfg.endpoints.length - leaks} isolated · ${leaks} leak(s)${inconclusive ? ` · ${inconclusive} inconclusive (refresh sessions & retry)` : ''}.`);
process.exit(leaks ? 1 : 0);
