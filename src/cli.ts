#!/usr/bin/env node
// src/cli.ts
// `npx github:newsengine/anal-probe <url> [options]`
// Point it at any deployed app and it reports everything wrong: leaked secrets, exposed files, broken
// links, missing security headers, SEO/a11y/performance gaps. Exits non-zero so it can gate CI.
//
//   --only security,secrets         only run these categories
//   --skip seo,a11y                 run everything except these
//   --cors-path /api/health         test CORS reflection on this path
//   --allow-report-only-csp         accept CSP Report-Only as a pass
//   --max-crawl 25                  how many links/scripts to fetch-check
//   --fail-on high|medium|any       CI exit threshold (default high)
//   --json                          machine-readable output

import { probe, summarize, ALL_CATEGORIES, type Category, type Finding, type Severity } from './probe.js';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const flag = (name: string) => process.argv.includes(name);
const list = (v?: string) => (v ? (v.split(',').map((s) => s.trim()).filter(Boolean) as Category[]) : undefined);

const SEV_ICON: Record<Severity, string> = { high: '🟥', medium: '🟧', low: '🟨', info: 'ℹ️ ' };
const CAT_TITLE: Record<Category, string> = {
  security: '🔐 Security', secrets: '🔑 Leaked secrets', exposure: '📂 Exposed files & debug',
  reliability: '🔗 Reliability', seo: '🔎 SEO', a11y: '♿ Accessibility', performance: '⚡ Performance',
};

async function main() {
  const url = process.argv[2];
  if (!url || url.startsWith('-')) {
    console.error('usage: npx github:newsengine/anal-probe <url> [--only ...] [--skip ...] [--cors-path <p>] [--fail-on high|medium|any] [--json]');
    process.exit(2);
  }

  const findings = await probe(url, {
    only: list(arg('--only')),
    skip: list(arg('--skip')),
    corsTestPath: arg('--cors-path'),
    allowReportOnlyCsp: flag('--allow-report-only-csp'),
    maxCrawl: arg('--max-crawl') ? Number(arg('--max-crawl')) : undefined,
  });
  const sum = summarize(findings);

  if (flag('--json')) {
    console.log(JSON.stringify({ url, summary: sum, findings }, null, 2));
  } else {
    console.log(`\n🔬 anal-probe — full app scan of ${url}\n`);
    for (const cat of ALL_CATEGORIES) {
      const group = findings.filter((f) => f.category === cat);
      if (!group.length) continue;
      const failed = group.filter((g) => !g.pass).length;
      console.log(`${CAT_TITLE[cat]}  ${failed ? `— ${failed} issue(s)` : '— ok'}`);
      for (const f of group as Finding[]) {
        const mark = f.pass ? '  ✅' : `  ${SEV_ICON[f.severity]}`;
        console.log(`${mark} [${f.severity.toUpperCase()}] ${f.title}`);
        console.log(`        ${f.detail}`);
        if (!f.pass && f.fix) console.log(`        ↳ fix: ${f.fix}`);
      }
      console.log('');
    }
    console.log(`${sum.passed} passed, ${sum.failed} failed  (🟥 ${sum.failHigh} high · 🟧 ${sum.failMedium} medium · 🟨 ${sum.failLow} low)\n`);
  }

  const failOn = (arg('--fail-on') || 'high') as 'high' | 'medium' | 'any';
  const shouldFail =
    failOn === 'any' ? sum.failed > 0 :
    failOn === 'medium' ? sum.failHigh + sum.failMedium > 0 :
    sum.failHigh > 0;
  process.exit(shouldFail ? 1 : 0);
}

main().catch((e) => { console.error('probe error:', e); process.exit(2); });
