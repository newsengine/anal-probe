#!/usr/bin/env node
// src/cli.ts
// `security-kit probe <url> [--cors-path /api/...] [--allow-report-only-csp] [--json] [--fail-on high|medium|any]`
// Runs the black-box probe and exits non-zero when failures at/above the threshold exist — so it gates CI.
import { probe, summarize } from './probe.js';
function arg(name) {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
}
function flag(name) {
    return process.argv.includes(name);
}
const SEV_ICON = { high: '🟥', medium: '🟧', low: '🟨', info: 'ℹ️ ' };
async function main() {
    const url = process.argv[2];
    if (!url || url.startsWith('-')) {
        console.error('usage: security-kit probe <url> [--cors-path <path>] [--allow-report-only-csp] [--json] [--fail-on high|medium|any]');
        process.exit(2);
    }
    const findings = await probe(url, {
        corsTestPath: arg('--cors-path'),
        allowReportOnlyCsp: flag('--allow-report-only-csp'),
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
