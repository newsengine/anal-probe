// examples/separation-of-accounts.mjs
//
// Cross-account / multi-tenant (IDOR) test: prove that account B CANNOT read or mutate account A's
// resources. Black-box, no framework — drives the shipped `idorProbe` helper. Safe & non-destructive
// by default (GETs only); it just asserts the server DENIES the attacker.
//
// HOW TO USE (agentaus.com.au or any app):
//   1. Log in as ACCOUNT A in a browser, open DevTools → Application → Cookies, copy the session cookie
//      (NextAuth: `__Secure-next-auth.session-token` or `next-auth.session-token`, or `authjs.session-token`).
//   2. While logged in as A, open DevTools → Network, click around, and copy 2–3 request URLs that return
//      A's OWN data and contain an id (e.g. /api/orgs/<A_ORG>/members, /api/projects/<A_PROJECT_ID>).
//   3. Log in as ACCOUNT B in a separate browser/profile and copy B's session cookie the same way.
//   4. Fill A_COOKIE, B_COOKIE and the CASES below, then run:
//        node examples/separation-of-accounts.mjs
//      (or pass via env: A_COOKIE='...' B_COOKIE='...' node examples/separation-of-accounts.mjs)
//
// A `LEAK` line = account B was allowed to touch account A's resource = a real separation-of-accounts bug.

import { idorProbe } from '../dist/testkit.js';

const ORIGIN = process.env.ORIGIN || 'https://agentaus.com.au';

// Account A owns the resources; account B is the "attacker" who must be denied.
const A_COOKIE = process.env.A_COOKIE || 'PASTE_ACCOUNT_A_SESSION_COOKIE_HERE';
const B_COOKIE = process.env.B_COOKIE || 'PASTE_ACCOUNT_B_SESSION_COOKIE_HERE';

// The attacker (account B). idorProbe sends these headers with every request below.
const attacker = {
  label: 'account B (mikenicholls88@gmail.com)',
  headers: { cookie: B_COOKIE, accept: 'application/json' },
};

// Each case is a resource that belongs to ACCOUNT A. We try to reach it AS ACCOUNT B and expect a denial
// (401/403/404). Replace the URLs with real A-owned endpoints captured from A's Network tab in step 2.
const cases = [
  // { name: 'A org members',   request: () => ({ url: `${ORIGIN}/api/orgs/A_ORG_ID/members` }) },
  // { name: 'A project detail', request: () => ({ url: `${ORIGIN}/api/projects/A_PROJECT_ID` }) },
  // { name: 'A user profile',   request: () => ({ url: `${ORIGIN}/api/users/A_USER_ID` }) },
];

if (!cases.length) {
  console.error('No CASES defined yet. Add A-owned resource URLs (see the header comment) and re-run.');
  process.exit(2);
}
if (A_COOKIE.startsWith('PASTE_') || B_COOKIE.startsWith('PASTE_')) {
  console.error('Set A_COOKIE and B_COOKIE (env vars or edit the file) before running.');
  process.exit(2);
}

// Sanity: confirm the cookies actually authenticate as two DIFFERENT accounts before trusting the result.
async function whoami(cookie) {
  const r = await fetch(`${ORIGIN}/api/auth/session`, { headers: { cookie, accept: 'application/json' } });
  return r.ok ? await r.text() : `(session fetch ${r.status})`;
}
console.log('Account A session:', (await whoami(A_COOKIE)).slice(0, 200));
console.log('Account B session:', (await whoami(B_COOKIE)).slice(0, 200));
console.log('');

const results = await idorProbe(attacker, cases);
let leaks = 0;
for (const r of results) {
  console.log(`${r.ok ? '✅' : '🟥 LEAK'}  ${r.name}: ${r.detail}`);
  if (!r.ok) leaks++;
}
console.log(`\n${results.length - leaks}/${results.length} correctly denied, ${leaks} leak(s).`);
process.exit(leaks ? 1 : 0);
