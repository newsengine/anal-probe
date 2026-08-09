// Agent-facing security review report — same shape as the Sparkle "findings-for-agent" markdown
// and Claude Code security artifacts: ranked P1/P2/… items with standards, problem, where, fix, verify.

import type { Finding, Severity } from './types.js';
import { refsFor, securityGrade, tlsGrade, OWASP_TOP10_NAMES } from './compliance.js';

const SEV_RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
const SEV_ICON: Record<Severity, string> = { high: '🟥', medium: '🟧', low: '🟨', info: 'ℹ️' };
const SEV_LABEL: Record<Severity, string> = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };

export interface AgentReportOptions {
  url: string;
  projectName?: string;
  generatedAt?: string;
  /** Extra caveats (e.g. embeddable widget note). */
  caveats?: string[];
  /** Include passing checks summary at the end. */
  includePassed?: boolean;
}

function standardsLine(id: string): string {
  const r = refsFor(id);
  const parts: string[] = [];
  if (r.cwe?.length) parts.push(r.cwe.join(' / '));
  if (r.owasp) parts.push(`OWASP ${r.owasp}${OWASP_TOP10_NAMES[r.owasp] ? ` (${OWASP_TOP10_NAMES[r.owasp]})` : ''}`);
  if (r.asvs?.length) parts.push(`ASVS ${r.asvs.join(', ')}`);
  if (r.wstg?.length) parts.push(r.wstg.join(', '));
  if (r.apiTop10) parts.push(r.apiTop10);
  return parts.length ? parts.join(' · ') : 'general hygiene';
}

function whereHint(f: Finding): string {
  if (f.category === 'secrets') return 'Browser-shipped JS bundles / HTML — `grep` for the secret pattern, check env leakage in Next/Vite build.';
  if (f.category === 'exposure') return 'Public HTTP paths (SPA catch-alls can false-positive; body was validated). Check deploy config and static hosting rules.';
  if (f.category === 'dns') return 'DNS zone at your registrar/CDN (Cloudflare/Route53/…).';
  if (f.category === 'security') return 'Response headers / TLS / cookies — `_headers`, `vercel.json`, middleware, reverse proxy, or framework config.';
  if (f.category === 'framework') return 'Stack-specific surface for the detected framework (Next/WP/Laravel/…).';
  if (f.category === 'components') return 'Client-side script/link URLs loading vulnerable libraries.';
  if (f.category === 'agent') return 'HTML + `/llms.txt` + `robots.txt` + `/.well-known` agent manifests.';
  if (f.category === 'seo' || f.category === 'a11y' || f.category === 'performance' || f.category === 'reliability') {
    return 'App shell / marketing HTML and static assets.';
  }
  return `Category \`${f.category}\` — search the repo for related config/handlers.`;
}

function verifyHint(url: string, f: Finding): string {
  return [
    `npx github:newsengine/vibetesting-agent ${url} --only ${f.category}`,
    `Confirm finding \`${f.id}\` no longer fails.`,
  ].join('; ');
}

/**
 * Render a prioritized agent fix / security-review markdown document.
 * Matches the structure used in reports/sparkle-findings-for-agent.md.
 */
export function renderAgentReport(findings: Finding[], opts: AgentReportOptions): string {
  const when = opts.generatedAt ?? new Date().toISOString().slice(0, 10);
  const grade = securityGrade(findings);
  const tls = tlsGrade(findings);
  const fails = findings
    .filter((f) => !f.pass)
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.title.localeCompare(b.title));
  const passed = findings.filter((f) => f.pass);

  const lines: string[] = [];
  const title = opts.projectName || opts.url;
  lines.push(`# ${title} — security & readiness findings`);
  lines.push('');
  lines.push(`**For:** the coding agent working on this repo.`);
  lines.push(`**Source:** black-box scan via vibetesting-agent, ${when}. **Grade:** security **${grade.grade} (${grade.score}/100)**, TLS **${tls}**.`);
  lines.push(
    `**Overall:** ${fails.length === 0 ? 'no open hygiene failures on this pass.' : `${fails.length} open issue(s) ranked below (high → low).`}`,
  );
  lines.push('');
  lines.push('> ⚠️ **Authorized use only.** Hygiene scan — first line of defense, not a pentest. A clean scan does not mean the app is secure.');
  if (opts.caveats?.length) {
    for (const c of opts.caveats) lines.push(`> ${c}`);
  }
  lines.push('');
  lines.push('---');
  lines.push('');

  if (fails.length === 0) {
    lines.push('## ✅ No failing findings');
    lines.push('');
    lines.push('Ship score is green for black-box hygiene. Keep deploy-triggered scans enabled and re-run after each software update.');
    lines.push('');
  } else {
    fails.forEach((f, i) => {
      const p = `P${i + 1}`;
      lines.push(`## ${p} — ${f.title}  ${SEV_ICON[f.severity]} ${SEV_LABEL[f.severity]}`);
      lines.push(`- **${standardsLine(f.id)}**`);
      lines.push(`- **id:** \`${f.id}\` · **category:** \`${f.category}\``);
      lines.push(`- **Problem:** ${f.detail}`);
      lines.push(`- **Where:** ${whereHint(f)}`);
      lines.push(`- **Fix:** ${f.fix || 'Investigate and harden this surface with least privilege and safe defaults.'}`);
      lines.push(`- **Verify (accept):** ${verifyHint(opts.url, f)}`);
      lines.push('');
    });
  }

  lines.push('---');
  lines.push('');
  lines.push('## Agent instructions');
  lines.push('');
  lines.push('1. Work **top-down** (P1 first). Do not invent secrets or weaken auth to make a check pass.');
  lines.push('2. Prefer reversible, scoped fixes (route-level headers over global if the app has public embeds).');
  lines.push('3. After each fix, re-run the verify command for that finding.');
  lines.push(`4. Full rescan: \`npx github:newsengine/vibetesting-agent ${opts.url} --agent-report security-review.md\``);
  lines.push('5. Optional: implement Gherkin scenarios under `features/security/` and wire them to your test runner.');
  lines.push('');

  if (opts.includePassed !== false && passed.length) {
    lines.push('## ✅ Passing checks (no action)');
    lines.push('');
    const byCat = new Map<string, number>();
    for (const f of passed) byCat.set(f.category, (byCat.get(f.category) || 0) + 1);
    for (const [cat, n] of [...byCat.entries()].sort()) {
      lines.push(`- **${cat}:** ${n} pass`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(`*Generated by vibetesting-agent agent-report · ${opts.url}*`);
  lines.push('');
  return lines.join('\n');
}

/** One-finding clipboard prompt for Cursor/Claude. */
export function renderFindingPrompt(url: string, f: Finding): string {
  return [
    `Fix this vibetesting-agent finding on ${url}:`,
    ``,
    `ID: ${f.id}`,
    `Severity: ${f.severity}`,
    `Category: ${f.category}`,
    `Title: ${f.title}`,
    `Standards: ${standardsLine(f.id)}`,
    `Detail: ${f.detail}`,
    `Recommended fix: ${f.fix || 'Harden this surface safely.'}`,
    `Where: ${whereHint(f)}`,
    ``,
    `Verify: ${verifyHint(url, f)}`,
  ].join('\n');
}
