import type { Finding, Severity } from './types.js';
import { summarize } from './probe.js';
export type Priority = 'critical' | 'high' | 'medium' | 'low' | 'clean';
/** One executed check within a run. */
export interface SubTestResult {
    number: number | null;
    code: string;
    id: string;
    category: string;
    severity: Severity;
    pass: boolean;
    detail: string;
    atlas?: string[];
}
/** A full run of the test set for one target — the row a database stores. */
export interface RunRecord {
    runId: string;
    runNumber: number | null;
    target: string;
    actor: string;
    startedAt: string;
    finishedAt: string;
    durationMs: number;
    priority: Priority;
    summary: ReturnType<typeof summarize>;
    subTests: SubTestResult[];
}
/** Headline priority from the summary + which checks failed. */
export declare function priorityOf(subTests: SubTestResult[]): Priority;
/** Build a run record (with every sub-test) from a scan's findings. */
export declare function buildRunRecord(findings: Finding[], opts: {
    target: string;
    actor?: string;
    startedAt?: string;
    finishedAt?: string;
    durationMs?: number;
    runId?: string;
    runNumber?: number | null;
}): RunRecord;
/** Read all run records from a JSONL ledger file ([] if missing/empty). */
export declare function readRuns(file: string): RunRecord[];
/** Append a run to the JSONL ledger, assigning the next monotonic run number for that target. Returns the stored record. */
export declare function appendRun(file: string, record: RunRecord): RunRecord;
/**
 * Render the Priority-Status report: a first-page banner (status + counts + trend vs the previous run),
 * the ranked failing sub-tests by VTA number, then a category roll-up. This is the daily report's cover.
 */
export declare function renderPriorityReport(record: RunRecord, previous?: RunRecord | null): string;
