#!/usr/bin/env node
// src/cli.ts
// `security-kit probe <url> [--cors-path /api/...] [--allow-report-only-csp] [--json] [--fail-on high|medium|any]`
// Runs the black-box probe and exits non-zero when failures at/above the threshold exist — so it gates CI.
import { probe, summarize } from './probe.js';
import { runNpmAudit, failsAtLevel } from './audit.js';
function arg(name) {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
}
function flag(name) {
    return process.argv.includes(name);
}
const SEV_ICON = { high: '🟥', medium: '🟧', low: '🟨', info: 'ℹ️ ' };
async function runAudit() {
    const level = arg('--level') || 'high';
    const result = await runNpmAudit(process.cwd(), flag('--prod'));
    if (flag('--json')) {
        console.log(JSON.stringify(result, null, 2));
    }
    else if (result.error) {
        console.error('audit error:', result.error);
    }
    else {
        console.log(`\n🔐 saas-security-kit audit (npm audit)\n`);
        for (const sev of ['critical', 'high', 'moderate', 'low', 'info'])
            console.log(`  ${sev}: ${result.counts[sev] ?? 0}`);
        console.log(`\n${result.total} total advisories\n`);
    }
    process.exit(result.error ? 2 : failsAtLevel(result, level) ? 1 : 0);
}
async function main() {
    if (process.argv[2] === 'audit')
        return runAudit();
    // probe is the default: `security-kit <url>` or `security-kit probe <url>`
    const url = process.argv[2] === 'probe' ? process.argv[3] : process.argv[2];
    if (!url || url.startsWith('-')) {
        console.error('usage:\n  security-kit <url> [--cors-path <path>] [--allow-report-only-csp] [--json] [--fail-on high|medium|any]\n  security-kit audit [--prod] [--level low|moderate|high|critical] [--json]');
        process.exit(2);
    }
    const findings = await probe(url, {
        corsTestPath: arg('--cors-path'),
        allowReportOnlyCsp: flag('--allow-report-only-csp'),
        rateLimitPath: arg('--rate-limit-path'),
    });
    const sum = summarize(findings);
    if (flag('--json')) {
        console.log(JSON.stringify({ url, summary: sum, findings }, null, 2));
    }
    else {
        console.log(`\n🔐 saas-security-kit probe — ${url}\n`);
        for (const f of findings) {
            const mark = f.pass ? '✅' : `${SEV_ICON[f.severity]}`;
            console.log(`${mark} [${f.severity.toUpperCase()}] ${f.title}\n     ${f.detail}`);
        }
        console.log(`\n${sum.passed} passed, ${sum.failed} failed (${sum.failHigh} high, ${sum.failMedium} medium)\n`);
    }
    const failOn = (arg('--fail-on') || 'high');
    const shouldFail = failOn === 'any' ? sum.failed > 0 :
        failOn === 'medium' ? sum.failHigh + sum.failMedium > 0 :
            sum.failHigh > 0;
    process.exit(shouldFail ? 1 : 0);
}
main().catch((e) => { console.error('probe error:', e); process.exit(2); });
