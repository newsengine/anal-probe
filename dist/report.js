// src/report.ts
// Renders a scan into a self-contained, print-friendly HTML report (open in a browser → Save as PDF, or
// use `--pdf` which renders it via the optional playwright-core battery). One table row per check, with
// result, severity, suggested fix, and the standards it maps to (CWE / ASVS / OWASP). Zero-dependency.
import { refsFor, asvsCoverage, securityGrade, tlsGrade, owaspTop10Hit, OWASP_TOP10_NAMES } from './compliance.js';
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const CAT = {
    security: 'Security', secrets: 'Leaked secrets', exposure: 'Exposed files & debug', dns: 'DNS & email',
    reliability: 'Reliability', seo: 'SEO', a11y: 'Accessibility', performance: 'Performance',
    agent: 'Agent readiness', framework: 'Framework', components: 'Vulnerable components', host: 'Host & infrastructure',
};
const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
function stdBadges(id) {
    const r = refsFor(id);
    const parts = [];
    if (r.owasp)
        parts.push(r.owasp);
    if (r.asvs?.length)
        parts.push(r.asvs[0]);
    if (r.cwe?.length)
        parts.push(r.cwe[0]);
    return parts.map((p) => `<span class="b">${esc(p)}</span>`).join(' ');
}
export function renderReport(url, findings, opts = {}) {
    const when = opts.generatedAt ?? new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    const failed = findings.filter((f) => !f.pass);
    const counts = { high: 0, medium: 0, low: 0 };
    for (const f of failed)
        if (f.severity in counts)
            counts[f.severity]++;
    const grade = securityGrade(findings);
    const tls = tlsGrade(findings);
    const cats = [...new Set(findings.map((f) => f.category))];
    const rows = (cat) => findings
        .filter((f) => f.category === cat)
        .sort((a, b) => (a.pass === b.pass ? SEV_ORDER[a.severity] - SEV_ORDER[b.severity] : a.pass ? 1 : -1))
        .map((f) => `<tr class="${f.pass ? 'ok' : f.severity}">
      <td class="sev"><span class="pill ${f.pass ? 'p' : f.severity}">${f.pass ? 'PASS' : f.severity.toUpperCase()}</span></td>
      <td class="ttl"><b>${esc(f.title)}</b><div class="det">${esc(f.detail)}</div></td>
      <td class="fix">${f.pass ? '<span class="muted">—</span>' : esc(f.fix || '—')}</td>
      <td class="std">${stdBadges(f.id)}</td>
    </tr>`).join('');
    const asvs = asvsCoverage(findings);
    const asvsN = (s) => asvs.filter((r) => r.status === s).length;
    const top10 = owaspTop10Hit(findings);
    return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>anal-probe report — ${esc(url)}</title>
<style>
  :root{--ink:#12161a;--mut:#5b6772;--line:#e4e8ec;--bg:#fff;--panel:#f7f9fa;
    --hi:#d1342b;--md:#c67a10;--lo:#8a7a12;--ok:#1f8a4c;--accent:#12161a}
  *{box-sizing:border-box}
  body{margin:0;background:#eef1f3;color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.55}
  .page{max-width:920px;margin:24px auto;background:var(--bg);border:1px solid var(--line);border-radius:10px;overflow:hidden}
  header{padding:30px 34px;border-bottom:2px solid var(--ink)}
  .logo{font-family:ui-monospace,'SF Mono',Menlo,monospace;font-weight:800;letter-spacing:-.02em;font-size:15px}
  .logo b{color:#3aa856}
  h1{font-size:22px;margin:14px 0 4px;letter-spacing:-.01em;word-break:break-all}
  .meta{color:var(--mut);font-size:13px}
  .grades{display:flex;gap:26px;margin-top:20px;flex-wrap:wrap}
  .g{border:1px solid var(--line);border-radius:8px;padding:12px 18px;min-width:120px;background:var(--panel)}
  .g .n{font-size:30px;font-weight:800;line-height:1;font-family:ui-monospace,monospace}
  .g .l{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);margin-top:6px}
  .g.a .n{color:var(--ok)} .g.b .n{color:var(--md)} .g.f .n{color:var(--hi)}
  .chips{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap;font-size:13px}
  .chips span{border:1px solid var(--line);border-radius:6px;padding:5px 11px;font-family:ui-monospace,monospace}
  .chips .h{color:var(--hi)} .chips .m{color:var(--md)} .chips .l{color:var(--lo)} .chips .o{color:var(--ok)}
  section{padding:22px 34px}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.12em;color:var(--mut);margin:26px 0 10px;
    border-bottom:1px solid var(--line);padding-bottom:8px}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);
    padding:7px 8px;border-bottom:1px solid var(--line)}
  td{padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}
  tr.ok td{opacity:.72}
  .pill{font-family:ui-monospace,monospace;font-size:10px;font-weight:700;padding:3px 7px;border-radius:5px;
    color:#fff;white-space:nowrap;letter-spacing:.03em}
  .pill.high{background:var(--hi)} .pill.medium{background:var(--md)} .pill.low{background:var(--lo)}
  .pill.p{background:var(--ok)}
  .sev{width:70px} .ttl{width:44%} .det{color:var(--mut);font-size:12.5px;margin-top:3px}
  .fix{font-size:12.5px;color:#243}
  .std{width:120px}
  .std .b{display:inline-block;font-family:ui-monospace,monospace;font-size:10.5px;color:var(--mut);
    border:1px solid var(--line);border-radius:4px;padding:1px 5px;margin:0 2px 3px 0}
  .muted{color:#aab}
  .asvs{display:flex;flex-direction:column;font-size:13px;font-family:ui-monospace,monospace}
  .asvs div{padding:8px 10px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:baseline}
  .asvs div:last-child{border-bottom:none}
  .asvs .mk{width:14px;flex-shrink:0;font-weight:700}
  .asvs .id{color:var(--mut);min-width:66px;flex-shrink:0}
  .asvs .tx{color:var(--ink)}
  .asvs .pass .mk{color:var(--ok)} .asvs .fail .mk{color:var(--hi)}
  .asvs .no .mk{color:#99a} .asvs .no .tx{color:#8a94a0}
  .asvs .nc .mk{color:#bbc} .asvs .nc .tx{color:#9aa2ac}
  .asvs .fail .tx{color:var(--hi)}
  .obs{margin-top:6px}
  .obs h3{font-size:14.5px;margin:20px 0 8px;letter-spacing:-.01em}
  .obs ul{margin:0 0 6px;padding-left:20px}
  .obs li{font-size:13.5px;color:#233;margin:5px 0}
  footer{padding:20px 34px;color:var(--mut);font-size:12px;border-top:1px solid var(--line)}
  @media print{body{background:#fff}.page{border:none;margin:0;max-width:none}
    section,header,footer{padding-left:0;padding-right:0}.page{border-radius:0}
    tr{break-inside:avoid}}
</style></head><body><div class="page">
<header>
  <div class="logo">anal<b>-</b>probe · security &amp; deploy-health report</div>
  <h1>${esc(url)}</h1>
  <div class="meta">Generated ${esc(when)} · black-box scan, ${findings.length} checks across ${cats.length} categories</div>
  <div class="grades">
    <div class="g ${grade.grade[0] === 'A' ? 'a' : grade.grade === 'F' || grade.grade === 'D' ? 'f' : 'b'}"><div class="n">${grade.grade}</div><div class="l">Security · ${grade.score}/100</div></div>
    <div class="g ${tls[0] === 'A' ? 'a' : tls === 'F' ? 'f' : 'b'}"><div class="n">${tls}</div><div class="l">TLS grade</div></div>
    <div class="g"><div class="n">${failed.length}</div><div class="l">Findings</div></div>
  </div>
  <div class="chips">
    <span class="h">${counts.high} High</span><span class="m">${counts.medium} Medium</span>
    <span class="l">${counts.low} Low</span><span class="o">${findings.length - failed.length} Passed</span>
  </div>
</header>
<section>
  <h2>Findings by category</h2>
  ${cats.map((c) => `<h2 style="border:none;color:var(--ink);letter-spacing:-.01em;text-transform:none;font-size:15px;margin:22px 0 6px">${esc(CAT[c] || c)}</h2>
    <table><thead><tr><th class="sev">Result</th><th>Check &amp; detail</th><th>Suggested fix / mitigation</th><th>Standards</th></tr></thead>
    <tbody>${rows(c)}</tbody></table>`).join('')}
</section>
${opts.observations?.length ? `<section>
  <h2>UX &amp; operational observations</h2>
  <div class="obs">${opts.observations.map((g) => `<h3>${esc(g.heading)}</h3><ul>${g.points.map((p) => `<li>${esc(p)}</li>`).join('')}</ul>`).join('')}</div>
</section>` : ''}
<section>
  <h2>OWASP ASVS 4.0.3 — Level 1 coverage (${asvsN('pass')} pass · ${asvsN('fail')} fail · ${asvsN('not-observed')} not-observed · ${asvsN('not-covered')} n/a)</h2>
  <div class="asvs">${asvs.map((r) => {
        const cls = r.status === 'pass' ? 'pass' : r.status === 'fail' ? 'fail' : r.status === 'not-observed' ? 'no' : 'nc';
        const mk = r.status === 'pass' ? '✓' : r.status === 'fail' ? '✗' : '·';
        return `<div class="${cls}"><span class="mk">${mk}</span><span class="id">${esc(r.id)}</span><span class="tx">${esc(r.text)}</span></div>`;
    }).join('')}</div>
  ${Object.keys(top10).length ? `<h2>OWASP Top 10 (2021) — open issue categories</h2><div class="asvs">${Object.keys(top10).sort().map((k) => `<div class="fail"><span class="mk">✗</span><span class="id">${esc(k)}</span><span class="tx">${esc(OWASP_TOP10_NAMES[k])} — ${top10[k]} issue(s)</span></div>`).join('')}</div>` : ''}
</section>
<footer>Generated by anal-probe · black-box scan (no source, no attack payloads). Findings are signature-validated to minimise false positives; verify high-severity items in context before remediation. Standards mapping is informational.</footer>
</div></body></html>`;
}
