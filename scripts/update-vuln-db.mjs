#!/usr/bin/env node
// scripts/update-vuln-db.mjs
// Regenerate src/vuln-data.ts from the retire.js community vulnerability feed. Zero dependencies:
// global fetch + node:fs/node:path only. Safe + idempotent: on fetch failure it exits non-zero WITHOUT
// clobbering the existing generated file. Merges the live feed with the hand-curated seed (union by
// library, dedupe by below+ref) so a curated entry is never dropped just because the feed lacks it.
//
// Usage: npm run update-vuln-db   (or: node scripts/update-vuln-db.mjs)

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_FILE = join(__dirname, '..', 'src', 'vuln-data.ts');

const FEED_URLS = [
  'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-master.json',
  'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json',
];

// anal-probe detector keys → candidate retire.js component names (lowercased, matched case-insensitively).
// Only these libraries have detectors in src/components.ts, so only these are pulled from the feed.
const LIBRARY_MAP = {
  jquery: ['jquery'],
  'jquery-ui': ['jquery-ui', 'jquery-ui-dialog', 'jquery-ui-autocomplete', 'jquery-ui-tooltip'],
  bootstrap: ['bootstrap'],
  lodash: ['lodash'],
  angular: ['angularjs', 'angular'],
  handlebars: ['handlebars', 'handlebars.js'],
  moment: ['moment.js', 'moment'],
  axios: ['axios'],
  dompurify: ['dompurify'],
  vue: ['vue', 'vue.js'],
  underscore: ['underscore.js', 'underscore'],
  select2: ['select2'],
};

// The hand-curated seed. Kept in-tree so the feed can never DROP a curated advisory. Union-merged with the
// feed (dedupe by below+ref). Mirrors the original VULN_DB that shipped in components.ts.
const SEED = {
  jquery: [
    { below: '3.5.0', severity: 'medium', ref: 'CVE-2020-11022/11023', note: 'XSS via jQuery.htmlPrefilter when passing untrusted HTML to DOM-manipulation methods' },
    { below: '1.9.0', severity: 'medium', ref: 'CVE-2012-6708', note: 'selector-based XSS in very old jQuery' },
  ],
  'jquery-ui': [
    { below: '1.13.2', severity: 'medium', ref: 'CVE-2022-31160', note: 'XSS in the checkboxradio widget when refreshing with untrusted labels' },
  ],
  angular: [
    { below: '1.8.3', severity: 'high', ref: 'AngularJS EOL + multiple XSS/sandbox-escape CVEs', note: 'AngularJS 1.x is end-of-life (no security fixes); multiple known XSS/CSP-bypass issues' },
  ],
  bootstrap: [
    { below: '3.4.1', severity: 'medium', ref: 'CVE-2019-8331', note: 'XSS in data-template / tooltip/popover (Bootstrap 3.x)' },
    { below: '4.3.1', severity: 'medium', ref: 'CVE-2019-8331', note: 'XSS in data-template (Bootstrap 4.x < 4.3.1)' },
  ],
  lodash: [
    { below: '4.17.21', severity: 'high', ref: 'CVE-2021-23337 / CVE-2020-8203', note: 'command injection via _.template and prototype pollution' },
  ],
  underscore: [
    { below: '1.13.0', severity: 'high', ref: 'CVE-2021-23358', note: 'arbitrary code execution via the template function' },
  ],
  moment: [
    { below: '2.29.4', severity: 'medium', ref: 'CVE-2022-31129', note: 'ReDoS parsing very long date strings (also: Moment is in maintenance mode)' },
  ],
  handlebars: [
    { below: '4.7.7', severity: 'high', ref: 'CVE-2021-23369 / CVE-2021-23383', note: 'prototype-pollution → RCE in the template compiler' },
  ],
  axios: [
    { below: '0.21.1', severity: 'medium', ref: 'CVE-2020-28168', note: 'SSRF via redirect handling' },
    { below: '1.6.0', severity: 'medium', ref: 'CVE-2023-45857', note: 'leaks the XSRF-TOKEN to third-party hosts on cross-origin requests' },
  ],
  dompurify: [
    { below: '3.0.9', severity: 'medium', ref: 'multiple mXSS bypasses (e.g. CVE-2024-45801)', note: 'mutation-XSS sanitizer bypasses — upgrade to the latest 3.x' },
  ],
  vue: [
    { below: '3.0.0', severity: 'low', ref: 'Vue 2 EOL (Dec 2023)', note: 'Vue 2.x is end-of-life; no further security patches' },
  ],
  select2: [
    { below: '4.0.6', severity: 'medium', ref: 'GHSA select2 XSS', note: 'XSS via unescaped option rendering' },
  ],
};

// ---- pure, exported helpers (unit-testable) ----

/** Normalize a retire.js / advisory severity string to anal-probe's high|medium|low. */
export function normalizeSeverity(sev) {
  const s = String(sev || '').toLowerCase().trim();
  if (s === 'critical' || s === 'high') return 'high';
  if (s === 'medium' || s === 'moderate') return 'medium';
  if (s === 'low' || s === 'info' || s === 'none') return 'low';
  return 'medium'; // unknown → conservative default
}

/** Best human ref for a retire.js vuln entry: prefer a CVE id, then a GHSA/github id, then summary/info URL. */
export function pickRef(entry) {
  const ids = entry.identifiers || {};
  if (Array.isArray(ids.CVE) && ids.CVE.length) return ids.CVE[0];
  const gh = ids.githubID;
  if (typeof gh === 'string' && gh.trim()) return gh.trim();
  if (Array.isArray(gh) && gh.length) return gh[0];
  const summary = entry.summary || (typeof ids.summary === 'string' ? ids.summary : '');
  if (typeof summary === 'string' && summary.trim()) return summary.trim().slice(0, 120);
  if (Array.isArray(entry.info) && entry.info.length) return String(entry.info[0]).slice(0, 120);
  return 'retire.js advisory';
}

/** The first-SAFE version for a retire.js range (the `below`/`atOrBelow` bound), or null if unbounded. */
function belowOfRange(range) {
  const b = range && (range.below || range.atOrBelow);
  return typeof b === 'string' && b ? String(b) : null;
}

/**
 * Map one retire.js component's `vulnerabilities[]` into anal-probe's {below,severity,ref,note}[] shape.
 * Each vuln has `ranges: [{ below?, atOrAbove? }]`; only ranges with a concrete `below` (first-safe version)
 * are usable by anal-probe's version-less-than matcher. One emitted entry per bounded range.
 */
export function mapRetireVulns(vulns) {
  const out = [];
  for (const entry of vulns || []) {
    // Newer feed nests bounds in `ranges[]`; tolerate an older flat `below` too.
    const ranges = Array.isArray(entry.ranges) && entry.ranges.length ? entry.ranges : [entry];
    const summaryRaw = entry.summary || (entry.identifiers && entry.identifiers.summary) || '';
    const summary = typeof summaryRaw === 'string' && summaryRaw.trim()
      ? summaryRaw.trim()
      : 'known vulnerability (retire.js community feed)';
    const severity = normalizeSeverity(entry.severity);
    const ref = pickRef(entry);
    for (const range of ranges) {
      const below = belowOfRange(range);
      if (!below) continue; // unbounded (atOrAbove-only) range — not expressible as "below"
      out.push({ below, severity, ref, note: summary.slice(0, 200) });
    }
  }
  return out;
}

/** Extract only anal-probe's libraries from the retire.js feed, keyed by anal-probe detector name. */
export function extractFromFeed(feed) {
  // Build a case-insensitive lookup of the feed's components.
  const lower = new Map();
  for (const k of Object.keys(feed || {})) lower.set(k.toLowerCase(), feed[k]);
  const result = {};
  for (const [ourKey, candidates] of Object.entries(LIBRARY_MAP)) {
    const entries = [];
    for (const cand of candidates) {
      const comp = lower.get(cand);
      if (comp && Array.isArray(comp.vulnerabilities)) entries.push(...mapRetireVulns(comp.vulnerabilities));
    }
    if (entries.length) result[ourKey] = entries;
  }
  return result;
}

/** Union-merge two tables by library; dedupe entries by below+ref. Seed order is preserved first. */
export function mergeTables(seed, feed) {
  const merged = {};
  const libs = new Set([...Object.keys(seed), ...Object.keys(feed)]);
  for (const lib of libs) {
    const seen = new Set();
    const list = [];
    for (const e of [...(seed[lib] || []), ...(feed[lib] || [])]) {
      const dedupeKey = `${e.below}::${e.ref}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      list.push(e);
    }
    if (list.length) merged[lib] = list;
  }
  return merged;
}

/** Render the generated src/vuln-data.ts source from a merged table + metadata. */
export function renderModule(table, meta) {
  const j = (s) => JSON.stringify(s);
  const libs = Object.keys(table).sort((a, b) => a.localeCompare(b));
  const body = libs.map((lib) => {
    const rows = table[lib].map(
      (e) => `    { below: ${j(e.below)}, severity: ${j(e.severity)}, ref: ${j(e.ref)}, note: ${j(e.note)} },`,
    ).join('\n');
    return `  ${j(lib)}: [\n${rows}\n  ],`;
  }).join('\n');

  return `// AUTO-GENERATED by scripts/update-vuln-db.mjs — do not edit by hand
// Known-vulnerable client-side JS library version ranges (retire.js-style). \`below\` = first SAFE version.
// Regenerate with: npm run update-vuln-db

export type VulnSeverity = 'high' | 'medium' | 'low';
export interface VulnEntry { below: string; severity: VulnSeverity; ref: string; note: string }

export const VULN_DATA: Record<string, VulnEntry[]> = {
${body}
};

export const VULN_DATA_META = {
  generatedAt: ${j(meta.generatedAt)},
  source: ${j(meta.source)},
  count: ${meta.count},
};
`;
}

async function fetchFeed() {
  let lastErr;
  for (const url of FEED_URLS) {
    try {
      const res = await fetch(url, { headers: { 'user-agent': 'anal-probe update-vuln-db' } });
      if (!res.ok) { lastErr = new Error(`HTTP ${res.status} for ${url}`); continue; }
      const json = await res.json();
      return { json, url };
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error('all feed URLs failed');
}

async function main() {
  let fetched;
  try {
    fetched = await fetchFeed();
  } catch (e) {
    console.error(`[update-vuln-db] FETCH FAILED: ${e && e.message ? e.message : e}`);
    console.error('[update-vuln-db] existing src/vuln-data.ts left untouched. Exiting non-zero.');
    process.exit(1);
    return;
  }

  const feedTable = extractFromFeed(fetched.json);
  const merged = mergeTables(SEED, feedTable);
  const count = Object.values(merged).reduce((n, arr) => n + arr.length, 0);
  const meta = {
    generatedAt: new Date().toISOString(),
    source: `retire.js community feed (${fetched.url}) + curated seed`,
    count,
  };

  const source = renderModule(merged, meta);
  writeFileSync(OUT_FILE, source, 'utf8');

  const libNames = Object.keys(merged).sort();
  console.log(`[update-vuln-db] wrote ${OUT_FILE}`);
  console.log(`[update-vuln-db] source: ${meta.source}`);
  console.log(`[update-vuln-db] libraries (${libNames.length}): ${libNames.join(', ')}`);
  console.log(`[update-vuln-db] total ranges: ${count}`);
  for (const lib of libNames) {
    const fromFeed = (feedTable[lib] || []).length;
    console.log(`  - ${lib}: ${merged[lib].length} ranges (${fromFeed} from feed)`);
  }
}

// Only run when invoked directly (allows importing the pure helpers from tests).
const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  main().catch((e) => {
    console.error(`[update-vuln-db] UNEXPECTED ERROR: ${e && e.stack ? e.stack : e}`);
    process.exit(1);
  });
}
