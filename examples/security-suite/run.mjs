// run.mjs — config-driven access-control suite. Generalized from an app-specific Playwright suite into
// checks that run against ANY deployed app given a URL + a few auth tokens. NO backend/test server,
// NO browser — plain fetch. Covers: auth enforcement + RBAC, owner-scoped data isolation, mass
// assignment / privilege escalation, and sensitive-field leakage.
//
//   node examples/security-suite/run.mjs config.json
//
// Config tokens can reference env vars as "${VAR}" so you don't commit secrets. config.json is gitignored.

import fs from 'node:fs';
import { rbacProbe, dataIsolationProbe, massAssignmentProbe, findSensitiveFields } from '../../dist/testkit.js';

const raw = fs.readFileSync(process.argv[2] || new URL('./config.json', import.meta.url), 'utf8');
const cfg = JSON.parse(raw.replace(/\$\{(\w+)\}/g, (_, v) => process.env[v] ?? ''));
const BASE = cfg.baseURL.replace(/\/$/, '');
const headersFor = (actor) => cfg.actors[actor]?.headers || {};
let failures = 0;
const line = (ok, msg) => { if (!ok) failures++; console.log(`${ok ? '✅' : '🟥'} ${msg}`); };

// ── 1. Auth enforcement + RBAC ────────────────────────────────────────────────
if (cfg.protectedEndpoints?.length) {
  console.log('\n── Auth enforcement & RBAC ──');
  for (const e of cfg.protectedEndpoints) {
    const actors = Object.keys(cfg.actors).map((name) => ({
      label: name,
      headers: headersFor(name),
      expect: (e.allow || []).includes(name) ? 'allow' : 'deny',
    }));
    const results = await rbacProbe(() => ({ url: BASE + e.path, init: { method: e.method || 'GET' } }), actors);
    for (const r of results) line(r.ok, `${e.name} — ${r.actor}: ${r.detail}`);
  }
}

// ── 2. Owner-scoped data isolation ────────────────────────────────────────────
if (cfg.ownerScopedLists?.length) {
  console.log('\n── Data isolation (owner-scoped lists) ──');
  for (const e of cfg.ownerScopedLists) {
    const extract = (body) => [...body.matchAll(new RegExp(e.idRegex, 'g'))].map((m) => m[1]);
    const res = await dataIsolationProbe(
      () => ({ url: BASE + e.path, init: { method: e.method || 'GET' } }),
      { label: e.userA, headers: headersFor(e.userA) },
      { label: e.userB, headers: headersFor(e.userB) },
      extract,
    );
    line(res.ok, `${e.name} — ${res.detail}`);
  }
}

// ── 3. Mass assignment / privilege escalation ─────────────────────────────────
if (cfg.massAssignment?.length) {
  console.log('\n── Mass assignment / privilege escalation ──');
  for (const e of cfg.massAssignment) {
    const res = await massAssignmentProbe(() => ({
      url: BASE + e.path,
      init: { method: e.method || 'POST', headers: { 'content-type': 'application/json', ...headersFor(e.as) }, body: JSON.stringify(e.body) },
    }), e.forgedValue);
    line(res.ok, `${e.name} — ${res.detail}`);
  }
}

// ── 4. Sensitive-field leakage on selected responses ──────────────────────────
if (cfg.sensitiveScan?.length) {
  console.log('\n── Sensitive-field leakage ──');
  for (const e of cfg.sensitiveScan) {
    const res = await fetch(BASE + e.path, { headers: headersFor(e.as) });
    const found = findSensitiveFields(await res.text(), cfg.sensitiveFields);
    line(found.length === 0, `${e.name} — ${found.length ? 'LEAKS ' + found.join(', ') : 'no sensitive fields returned'}`);
  }
}

console.log(`\n${failures ? '🟥' : '✅'} ${failures} failing check(s).`);
process.exit(failures ? 1 : 0);
