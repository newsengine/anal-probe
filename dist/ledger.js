// src/ledger.ts
// A test RUN and its SUB-TESTS, as a structured record — the unit that gets logged to a database (one
// `test_runs` row + one `test_results` row per sub-test) and drives the daily report. Each sub-test is
// keyed by its stable VTA number so results are comparable run-over-run and map to a GitHub issue.
//
// Zero-dependency: the record is a plain object (DB-ready), with a file-based JSONL ledger for the CLI.
// The hosted product persists the same shape to its D1 `test_runs`/`test_results` tables.
import { appendFileSync, readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { summarize } from './probe.js';
import { vtaNumber, vtaCode, catalogEntryFor } from './catalog.js';
// A failing HIGH in one of these is escalated to CRITICAL priority (leaked secret/data, exposed config,
// unauthenticated write, downloadable model, model data leak — the "someone is already exposed" set).
const CRITICAL_PREFIXES = ['secret.', 'exposed', 'debug-leak', 'api.unauth-write', 'atlas.model-artifact', 'atlas.data-leak'];
/** Headline priority from the summary + which checks failed. */
export function priorityOf(subTests) {
    const fails = subTests.filter((s) => !s.pass);
    if (!fails.length)
        return 'clean';
    const critical = fails.some((s) => s.severity === 'high' && CRITICAL_PREFIXES.some((p) => s.id.startsWith(p)));
    if (critical)
        return 'critical';
    if (fails.some((s) => s.severity === 'high'))
        return 'high';
    if (fails.some((s) => s.severity === 'medium'))
        return 'medium';
    if (fails.some((s) => s.severity === 'low'))
        return 'low';
    return 'clean';
}
/** Build a run record (with every sub-test) from a scan's findings. */
export function buildRunRecord(findings, opts) {
    const subTests = findings.map((f) => {
        const num = vtaNumber(f.id) ?? null;
        return {
            number: num, code: vtaCode(f.id), id: f.id, category: f.category, severity: f.severity, pass: f.pass,
            detail: f.detail, atlas: catalogEntryFor(f.id)?.atlas,
        };
    });
    const finishedAt = opts.finishedAt ?? new Date().toISOString();
    const startedAt = opts.startedAt ?? finishedAt;
    return {
        runId: opts.runId ?? randomUUID(),
        runNumber: opts.runNumber ?? null,
        target: opts.target,
        actor: opts.actor ?? 'cli',
        startedAt,
        finishedAt,
        durationMs: opts.durationMs ?? Math.max(0, Date.parse(finishedAt) - Date.parse(startedAt)),
        priority: priorityOf(subTests),
        summary: summarize(findings),
        subTests,
    };
}
// ── file-based JSONL ledger (the CLI's database-of-record; hosted product uses D1 instead) ────────────
/** Read all run records from a JSONL ledger file ([] if missing/empty). */
export function readRuns(file) {
    let raw = '';
    try {
        raw = readFileSync(file, 'utf8');
    }
    catch {
        return [];
    }
    return raw.split(/\r?\n/).filter(Boolean).map((l) => { try {
        return JSON.parse(l);
    }
    catch {
        return null;
    } }).filter((r) => !!r);
}
/** Append a run to the JSONL ledger, assigning the next monotonic run number for that target. Returns the stored record. */
export function appendRun(file, record) {
    const prior = readRuns(file).filter((r) => r.target === record.target);
    const runNumber = prior.reduce((m, r) => Math.max(m, r.runNumber ?? 0), 0) + 1;
    const stored = { ...record, runNumber };
    appendFileSync(file, JSON.stringify(stored) + '\n');
    return stored;
}
// ── the daily report — Priority Status on the first "page" ────────────────────────────────────────
const PRIORITY_BADGE = {
    critical: '🟥 CRITICAL', high: '🟥 HIGH', medium: '🟧 MEDIUM', low: '🟨 LOW', clean: '✅ CLEAN',
};
const SEV_RANK = { high: 0, medium: 1, low: 2, info: 3 };
/**
 * Render the Priority-Status report: a first-page banner (status + counts + trend vs the previous run),
 * the ranked failing sub-tests by VTA number, then a category roll-up. This is the daily report's cover.
 */
export function renderPriorityReport(record, previous) {
    const s = record.summary;
    const L = [];
    L.push('══════════════════════════════════════════════════════════════');
    L.push(`  PRIORITY STATUS: ${PRIORITY_BADGE[record.priority]}`);
    L.push(`  ${record.target}`);
    L.push(`  run #${record.runNumber ?? '—'} · ${record.finishedAt} · by ${record.actor}`);
    L.push('══════════════════════════════════════════════════════════════');
    L.push(`  ${s.passed} passed · ${s.failed} failed   (🟥 ${s.failHigh} high · 🟧 ${s.failMedium} medium · 🟨 ${s.failLow} low)`);
    if (previous) {
        const d = s.failed - previous.summary.failed;
        const trend = d === 0 ? 'no change' : d > 0 ? `▲ ${d} more failing than run #${previous.runNumber}` : `▼ ${-d} fewer failing than run #${previous.runNumber}`;
        L.push(`  trend: ${trend}`);
    }
    L.push('');
    const fails = record.subTests.filter((t) => !t.pass).sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || (a.number ?? 1e9) - (b.number ?? 1e9));
    if (fails.length) {
        L.push('  TOP ISSUES (by severity, keyed by test number):');
        for (const t of fails.slice(0, 20)) {
            const atlas = t.atlas?.length ? ` [${t.atlas.join(', ')}]` : '';
            L.push(`   ${t.code}  ${t.severity.toUpperCase().padEnd(6)} [${t.category}] ${t.id}${atlas}`);
            L.push(`            ${t.detail.slice(0, 100)}`);
        }
        if (fails.length > 20)
            L.push(`   … and ${fails.length - 20} more`);
    }
    else {
        L.push('  No failing checks. ✅');
    }
    L.push('');
    L.push('  BY CATEGORY:');
    for (const [cat, v] of Object.entries(s.byCategory).sort((a, b) => b[1].failed - a[1].failed)) {
        L.push(`   ${v.failed ? '🟥' : '✅'} ${cat.padEnd(12)} ${v.passed} ok · ${v.failed} failed`);
    }
    return L.join('\n') + '\n';
}
