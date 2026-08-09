// src/audit.ts
// White-box dependency audit: wraps `npm audit --json` in the current repo and summarizes by severity.
// Used as `vibetesting-agent audit [--prod] [--level low|moderate|high|critical]` to gate CI on vuln deps.
import { execFile } from 'node:child_process';
export function runNpmAudit(cwd = process.cwd(), prodOnly = false) {
    return new Promise((resolve) => {
        const args = ['audit', '--json', ...(prodOnly ? ['--omit=dev'] : [])];
        // npm audit exits non-zero when vulns exist — that's expected; we parse stdout regardless.
        execFile('npm', args, { cwd, maxBuffer: 64 * 1024 * 1024 }, (_err, stdout) => {
            try {
                const j = JSON.parse(stdout || '{}');
                const v = j.metadata?.vulnerabilities ?? {};
                const counts = {
                    info: v.info ?? 0, low: v.low ?? 0, moderate: v.moderate ?? 0, high: v.high ?? 0, critical: v.critical ?? 0,
                };
                const total = Object.values(counts).reduce((a, b) => a + b, 0);
                resolve({ counts, total, raw: j });
            }
            catch (e) {
                resolve({ counts: {}, total: 0, error: `could not parse npm audit output: ${String(e?.message || e)}` });
            }
        });
    });
}
const ORDER = ['info', 'low', 'moderate', 'high', 'critical'];
/** True if the audit has any vuln at or above `level`. */
export function failsAtLevel(result, level) {
    const idx = ORDER.indexOf(level);
    if (idx < 0)
        return result.total > 0;
    return ORDER.slice(idx).some((sev) => (result.counts[sev] ?? 0) > 0);
}
