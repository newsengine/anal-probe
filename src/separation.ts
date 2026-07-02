// src/separation.ts
// "Extra batteries" separation-of-accounts (multi-tenant) test: proves account B cannot read account A's
// data. Drives two of the user's real Chrome profiles (via browser-auth) so there are NO passwords to
// handle, lets each app fire its own authenticated requests, and for the attacker rewrites the tenant id
// to the owner's. Grades each endpoint with the shipped classifyTenantAccess. READ-ONLY (GET only) — it
// never submits forms or mutates data. Requires playwright-core + Chrome (loaded lazily).

import { setTenantParam, classifyTenantAccess, type TenantVerdict } from './testkit.js';
import { launchProfile, defaultProfilesDir } from './browser-auth.js';

export interface SeparationAccount { label: string; tenant: string; chromeProfile: string }
export interface SeparationConfig {
  origin: string;
  /** Query param carrying the tenant/org id (default tenant_uuid). */
  tenantParam?: string;
  chromeProfilesDir?: string;
  /** App pages to visit so it fires its authenticated API calls (default ['/']). */
  appPaths?: string[];
  owner: SeparationAccount;    // owns the resources
  attacker: SeparationAccount; // must be denied the owner's resources
  /** Tenant-scoped endpoints to test, matched by URL substring. */
  endpoints: { name: string; match: string }[];
}
export interface SeparationResult { name: string; verdict: TenantVerdict; reason: string; statuses: { baseline?: number; attack?: number; control?: number } }

export async function runSeparation(cfg: SeparationConfig): Promise<SeparationResult[]> {
  const tenantParam = cfg.tenantParam || 'tenant_uuid';
  const appPaths = cfg.appPaths || ['/'];
  const profilesDir = cfg.chromeProfilesDir || defaultProfilesDir();
  const labelOf = (u: string) => cfg.endpoints.find((e) => u.includes(e.match))?.name || null;

  const captureInto = (sink: Map<string, any>) => async (req: any) => {
    if (req.method() !== 'GET') return;
    const l = labelOf(req.url());
    if (!l || sink.has(l)) return;
    try { const res = await req.response(); if (res) sink.set(l, { status: res.status(), body: (await res.text()).slice(0, 2000) }); } catch {}
  };
  const nav = async (page: any) => {
    for (const p of appPaths) { await page.goto(cfg.origin + p, { waitUntil: 'networkidle', timeout: 30000 }).catch(() => {}); await page.waitForTimeout(2500); }
  };

  // 1) Owner baseline — what the owner's real data looks like (one launch).
  const owner = await launchProfile({ profilesDir, srcProfile: cfg.owner.chromeProfile, tag: 'owner', port: 9231 });
  const baseline = new Map<string, any>();
  try {
    const page = await (owner.browser.contexts()[0] || await owner.browser.newContext()).newPage();
    page.on('requestfinished', captureInto(baseline));
    await nav(page);
  } finally { await owner.close(); }

  // 2) Attacker — control then attack in ONE live session (keeps the rotating token valid).
  const att = await launchProfile({ profilesDir, srcProfile: cfg.attacker.chromeProfile, tag: 'att', port: 9232 });
  const control = new Map<string, any>();
  const attack = new Map<string, any>();
  try {
    const page = await (att.browser.contexts()[0] || await att.browser.newContext()).newPage();
    const ctlHandler = captureInto(control);
    page.on('requestfinished', ctlHandler);
    await nav(page);

    // Switch to attack: rewrite the tenant id → the owner's on the target endpoints, then re-navigate.
    page.off('requestfinished', ctlHandler);
    await page.route('**/*', (route: any) => {
      const u = route.request().url();
      if (route.request().method() === 'GET' && labelOf(u) && new RegExp(`${tenantParam}=`).test(u)) {
        return route.continue({ url: setTenantParam(u, cfg.owner.tenant, tenantParam) });
      }
      return route.continue();
    });
    page.on('requestfinished', captureInto(attack));
    await nav(page);
  } finally { await att.close(); }

  return cfg.endpoints.map((e) => {
    const b = baseline.get(e.name), a = attack.get(e.name), c = control.get(e.name);
    const { verdict, reason } = classifyTenantAccess({ baseline: b, attack: a, control: c });
    return { name: e.name, verdict, reason, statuses: { baseline: b?.status, attack: a?.status, control: c?.status } };
  });
}
