/**
 * Honest security-zone + OWASP WSTG / ASVS coverage catalog for the public docs page.
 * Mirrors vibetesting-agent's black-box philosophy: we map what we automate vs what needs auth/active tests.
 */

export type CoverageLevel = 'covered' | 'partial' | 'out';

export interface ZoneItem {
  title: string;
  detail: string;
  coverage: CoverageLevel;
  note?: string;
}

export interface SecurityZone {
  id: string;
  name: string;
  tagline: string;
  accent: string;
  items: ZoneItem[];
}

export const SECURITY_ZONES: SecurityZone[] = [
  {
    id: 'z0',
    name: 'Zone 0 — External / Internet edge',
    tagline: 'DNS · TLS · CDN · recon',
    accent: '#6b7c90',
    items: [
      {
        title: 'DNS & email hygiene',
        detail: 'SPF, DMARC, CAA, dangling-CNAME takeover heuristics',
        coverage: 'covered',
      },
      {
        title: 'TLS transport',
        detail: 'HTTPS, redirect, protocol/cipher grade, cert expiry, HSTS',
        coverage: 'covered',
      },
      {
        title: 'Host intel (passive)',
        detail: 'Resolve IPs, reverse DNS, CDN fingerprint',
        coverage: 'partial',
        note: 'recon mode opt-in for ports/CVE',
      },
      {
        title: 'OSINT recon',
        detail: 'Search engines, GitHub leaks, subdomain brute, archives',
        coverage: 'out',
      },
    ],
  },
  {
    id: 'z1',
    name: 'Zone 1 — Public web surface',
    tagline: 'Pages · headers · client assets',
    accent: '#3aa0ff',
    items: [
      {
        title: 'Security headers',
        detail: 'CSP, HSTS, nosniff, clickjacking, COOP/CORP, Permissions-Policy',
        coverage: 'covered',
      },
      {
        title: 'HTML / SEO / a11y hygiene',
        detail: 'Title, meta, canonical, lang, alt, labels, mixed content',
        coverage: 'covered',
      },
      {
        title: 'Client secrets & source maps',
        detail: 'Keys in bundles/HTML, downloadable .map files',
        coverage: 'covered',
      },
      {
        title: 'Vulnerable JS libraries',
        detail: 'retire.js-style version ranges (OWASP A06)',
        coverage: 'covered',
      },
      {
        title: 'DOM XSS · open redirect · SRI',
        detail: 'High-confidence client sinks, redirect params, third-party integrity',
        coverage: 'covered',
      },
      {
        title: 'Active XSS / SQLi fuzz',
        detail: 'Payload-driven injection across every field',
        coverage: 'out',
        note: 'not safe black-box on production',
      },
    ],
  },
  {
    id: 'z2',
    name: 'Zone 2 — Exposure & misconfig',
    tagline: 'Config · debug · backups',
    accent: '#2dd4a8',
    items: [
      {
        title: 'Exposed paths',
        detail: '.env, .git, backups, actuator, swagger, metrics…',
        coverage: 'covered',
      },
      {
        title: 'Framework footguns',
        detail: 'Next / WP / Laravel / Django / Rails / Spring / ASP.NET',
        coverage: 'covered',
      },
      {
        title: 'HTTP methods / CORS / TRACE',
        detail: 'Dangerous verbs, reflected Origin + credentials',
        coverage: 'covered',
      },
      {
        title: 'security.txt / robots / agent readiness',
        detail: 'Researcher contact + llms.txt style signals',
        coverage: 'covered',
      },
    ],
  },
  {
    id: 'z3',
    name: 'Zone 3 — Internal dashboard',
    tagline: 'Logged-in UI · workflows',
    accent: '#e6b422',
    items: [
      {
        title: 'AuthN / login flows',
        detail: 'WorkOS, MFA, lockout, password policy, session fixation',
        coverage: 'out',
        note: 'needs authenticated testing',
      },
      {
        title: 'Dashboard authorization',
        detail: 'Can user A see user B’s projects/scans?',
        coverage: 'partial',
        note: 'white-box IDOR helpers',
      },
      {
        title: 'CSRF on state-changing forms',
        detail: 'Heuristic on public HTML; full CSRF needs session',
        coverage: 'partial',
      },
      {
        title: 'Business logic',
        detail: 'Billing skips, race conditions, workflow abuse',
        coverage: 'out',
      },
    ],
  },
  {
    id: 'z4',
    name: 'Zone 4 — APIs, keys & webhooks',
    tagline: 'Bearer keys · MCP · Stripe · GitHub',
    accent: '#ff6b8a',
    items: [
      {
        title: 'API misconfig (public)',
        detail: 'GraphQL introspection, public swagger, method sprawl',
        coverage: 'covered',
      },
      {
        title: 'API authZ (BOLA / BFLA)',
        detail: 'Cross-user object access, role bypass',
        coverage: 'partial',
        note: 'testkit idor/rbac',
      },
      {
        title: 'API keys / JWT in browser',
        detail: 'Leaked keys + JWT hygiene (alg:none, exp)',
        coverage: 'covered',
      },
      {
        title: 'Webhook authenticity',
        detail: 'Stripe/GitHub signature verification bugs',
        coverage: 'out',
        note: 'app unit tests',
      },
    ],
  },
  {
    id: 'z5',
    name: 'Zone 5 — Account & tenant separation',
    tagline: 'Multi-tenant core',
    accent: '#b388ff',
    items: [
      {
        title: 'IDOR / horizontal privilege',
        detail: 'Tenant B reaches tenant A resources',
        coverage: 'partial',
        note: 'idorProbe / separation mode',
      },
      {
        title: 'RBAC / vertical privilege',
        detail: 'Anonymous / user / admin matrix',
        coverage: 'partial',
        note: 'rbacProbe',
      },
      {
        title: 'Mass assignment',
        detail: 'Client forges role / owner fields',
        coverage: 'partial',
        note: 'massAssignmentProbe',
      },
      {
        title: 'Data isolation on list APIs',
        detail: 'Shared IDs across two sessions',
        coverage: 'partial',
        note: 'dataIsolationProbe',
      },
    ],
  },
];

export interface WstgCategory {
  id: string;
  name: string;
  summary: string;
  coverage: CoverageLevel;
  examples: string[];
  how: string;
}

/** OWASP WSTG v4.2 testing categories — honest mapping to vibetesting-agent / VTA */
export const WSTG_CATEGORIES: WstgCategory[] = [
  {
    id: 'INFO',
    name: 'Information Gathering',
    summary: 'Fingerprint stack, metafiles, JS leakage, architecture mapping',
    coverage: 'partial',
    examples: ['WSTG-INFO-01 robots', 'WSTG-INFO-08 disclosure', 'source maps', 'host fingerprint'],
    how: 'Black-box homepage + passive host; not Google/GitHub/subdomain brute',
  },
  {
    id: 'CONF',
    name: 'Configuration & Deployment',
    summary: 'TLS, HTTP methods, debug surfaces, file exposure, security headers',
    coverage: 'covered',
    examples: ['WSTG-CONF-04 exposed paths', 'WSTG-CONF-06 methods', 'WSTG-CONF-07 HSTS', 'WSTG-CONF-12 CSP'],
    how: 'Core of the free + full black-box suite',
  },
  {
    id: 'IDNT',
    name: 'Identity Management',
    summary: 'Registration, account enumeration, provisioning',
    coverage: 'out',
    examples: ['duplicate registration', 'username enum', 'weak email verify'],
    how: 'Needs account lifecycle tests against the app',
  },
  {
    id: 'ATHN',
    name: 'Authentication',
    summary: 'Credential transport, lockout, MFA, default creds',
    coverage: 'partial',
    examples: ['WSTG-ATHN-01 rate-limit (opt-in)', 'TLS for credential channel'],
    how: 'Not full login abuse; WorkOS owns hosted auth',
  },
  {
    id: 'ATHZ',
    name: 'Authorization',
    summary: 'Privilege escalation, IDOR, path traversal',
    coverage: 'partial',
    examples: ['WSTG-ATHZ-04 IDOR via idorProbe', 'rbacProbe'],
    how: 'White-box helpers — not automatic from a single URL',
  },
  {
    id: 'SESS',
    name: 'Session Management',
    summary: 'Cookie flags, fixation, CSRF, logout',
    coverage: 'partial',
    examples: ['WSTG-SESS-02 cookies', 'WSTG-SESS-05 CSRF heuristic', 'WSTG-SESS-10 JWT'],
    how: 'Cookie/JWT/CSRF heuristics; not fixation or logout flows',
  },
  {
    id: 'INPV',
    name: 'Input Validation',
    summary: 'XSS, SQLi, SSRF, SSTI, LFI, command injection',
    coverage: 'partial',
    examples: ['WSTG-CLNT-01 DOM-XSS heuristic', 'WSTG-INPV-17 host-header'],
    how: 'No active payload fuzzing (by design on production targets)',
  },
  {
    id: 'ERRH',
    name: 'Error Handling',
    summary: 'Stack traces, verbose errors, information leakage',
    coverage: 'covered',
    examples: ['WSTG-ERRH-01 stack traces'],
    how: 'When error pages leak internals',
  },
  {
    id: 'CRYP',
    name: 'Cryptography',
    summary: 'Weak TLS, bad crypto, secrets in transit/storage',
    coverage: 'partial',
    examples: ['WSTG-CRYP-01 TLS', 'WSTG-CRYP-03 channel', 'WSTG-CRYP-04 client secrets'],
    how: 'Transport + client-exposed secrets; not server-side crypto review',
  },
  {
    id: 'BUSL',
    name: 'Business Logic',
    summary: 'Workflow abuse, races, price tampering, upload abuse',
    coverage: 'out',
    examples: ['checkout skip', 'race on quotas', 'file upload'],
    how: 'Manual / product-specific E2E',
  },
  {
    id: 'CLNT',
    name: 'Client-side',
    summary: 'DOM XSS, clickjacking, CORS, storage, SRI',
    coverage: 'covered',
    examples: ['WSTG-CLNT-01', 'WSTG-CLNT-04 open redirect', 'WSTG-CLNT-07 CORS', 'WSTG-CLNT-09 clickjacking', 'WSTG-CLNT-11 SRI'],
    how: 'Strong black-box coverage of client surface',
  },
  {
    id: 'APIT',
    name: 'API Testing',
    summary: 'REST/GraphQL authz, mass assignment, inventory',
    coverage: 'partial',
    examples: ['GraphQL introspection', 'swagger exposure', 'API1 via idorProbe', 'mass assignment helper'],
    how: 'Public misconfig automatic; BOLA needs two sessions',
  },
];

export interface AsvsRow {
  id: string;
  text: string;
  covered: boolean;
}

/** ASVS 4.0.3 Level 1 black-box subset (aligned with vibetesting-agent) */
export const ASVS_L1_ROWS: AsvsRow[] = [
  { id: 'V3.4.1–4', text: 'Session cookie Secure / HttpOnly / SameSite / __Host-', covered: true },
  { id: 'V3.4.5', text: 'Cookie Path scoped tightly', covered: false },
  { id: 'V7.4.1', text: 'Generic errors, no stack traces', covered: true },
  { id: 'V8.2.1', text: 'Anti-caching on sensitive responses', covered: true },
  { id: 'V9.1.1–3', text: 'TLS everywhere, strong ciphers & protocols', covered: true },
  { id: 'V12.5.1', text: 'Backup/temp files not web-served', covered: true },
  { id: 'V13.1.3', text: 'URLs/client code do not expose secrets', covered: true },
  { id: 'V14.2.2–3', text: 'No sample/debug surfaces; SRI on external assets', covered: true },
  { id: 'V14.3.2–3', text: 'Debug off; no version banners', covered: true },
  { id: 'V14.4.1', text: 'Content-Type + charset', covered: true },
  { id: 'V14.4.2', text: 'Content-Disposition on API responses', covered: false },
  { id: 'V14.4.3–7', text: 'CSP, nosniff, HSTS, Referrer-Policy, clickjacking', covered: true },
  { id: 'V14.5.1', text: 'HTTP methods restrained', covered: true },
  { id: 'V14.5.3', text: 'CORS not wide-open with credentials', covered: true },
];

export function coverageLabel(c: CoverageLevel): string {
  if (c === 'covered') return 'Covered';
  if (c === 'partial') return 'Partial';
  return 'Out of scope';
}

export function coverageCounts(items: { coverage: CoverageLevel }[]) {
  return {
    covered: items.filter((i) => i.coverage === 'covered').length,
    partial: items.filter((i) => i.coverage === 'partial').length,
    out: items.filter((i) => i.coverage === 'out').length,
    total: items.length,
  };
}
