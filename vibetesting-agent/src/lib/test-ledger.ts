/**
 * #32 — run-ledger persistence. Writes each completed scan as a test_runs row plus one test_results row
 * per SUB-TEST (keyed by its VTA number), and reads history for the daily report. Additive and defensive:
 * recordRun() must never throw into the scan pipeline (callers wrap it, and it swallows its own errors).
 */
import { and, desc, eq } from 'drizzle-orm';
import { getDb, schema } from './db';
import type { TestRun, TestResult } from './db/schema';
import type { Finding } from './scanner';
import { vtaNumber } from './vta-numbers';

export type Priority = 'critical' | 'high' | 'medium' | 'low' | 'clean';

// A failing HIGH in one of these escalates the whole run to CRITICAL (leaked secret/data, exposed config,
// unauth write, downloadable model, model data leak).
const CRITICAL_PREFIXES = ['secret.', 'exposed', 'debug-leak', 'api.unauth-write', 'atlas.model-artifact', 'atlas.data-leak'];

export function priorityOf(findings: Finding[]): Priority {
  const fails = findings.filter((f) => !f.pass && f.severity !== 'info');
  if (!fails.length) return 'clean';
  if (fails.some((f) => f.severity === 'high' && CRITICAL_PREFIXES.some((p) => f.id.startsWith(p)))) return 'critical';
  if (fails.some((f) => f.severity === 'high')) return 'high';
  if (fails.some((f) => f.severity === 'medium')) return 'medium';
  if (fails.some((f) => f.severity === 'low')) return 'low';
  return 'clean';
}

export interface RecordRunInput {
  scanId?: string; userId: string; projectId?: string | null; target: string;
  actor: string; trigger?: string; findings: Finding[];
  startedAt?: Date; finishedAt?: Date;
}

/** Persist a run + its sub-tests. Returns the stored run, or null on any error (never throws). */
export async function recordRun(input: RecordRunInput): Promise<TestRun | null> {
  try {
    const db = await getDb();
    const finishedAt = input.finishedAt ?? new Date();
    const startedAt = input.startedAt ?? finishedAt;

    // monotonic run number per (user, target)
    const prior = await db.select({ n: schema.testRuns.runNumber })
      .from(schema.testRuns)
      .where(and(eq(schema.testRuns.userId, input.userId), eq(schema.testRuns.target, input.target)))
      .orderBy(desc(schema.testRuns.runNumber)).limit(1);
    const runNumber = (prior[0]?.n ?? 0) + 1;

    const fails = input.findings.filter((f) => !f.pass && f.severity !== 'info');
    const runId = crypto.randomUUID();
    const run = {
      id: runId, scanId: input.scanId ?? null, userId: input.userId, projectId: input.projectId ?? null,
      runNumber, target: input.target, actor: input.actor, trigger: input.trigger ?? null,
      priority: priorityOf(input.findings),
      passed: input.findings.filter((f) => f.pass).length,
      failed: fails.length,
      failHigh: fails.filter((f) => f.severity === 'high').length,
      failMedium: fails.filter((f) => f.severity === 'medium').length,
      failLow: fails.filter((f) => f.severity === 'low').length,
      startedAt, finishedAt, createdAt: new Date(),
    };
    await db.insert(schema.testRuns).values(run);

    const results = input.findings.map((f) => ({
      id: crypto.randomUUID(), runId, vtaNumber: vtaNumber(f.id), checkId: f.id,
      category: f.category, severity: f.severity, pass: f.pass, detail: f.detail?.slice(0, 2000) ?? null,
      atlas: null as string | null,
    }));
    // D1 has a bound-parameter cap; insert in chunks to stay well under it.
    for (let i = 0; i < results.length; i += 50) await db.insert(schema.testResults).values(results.slice(i, i + 50));

    return (await db.select().from(schema.testRuns).where(eq(schema.testRuns.id, runId)).limit(1))[0] ?? null;
  } catch (e) {
    console.error('recordRun failed (non-fatal):', String((e as Error)?.message || e));
    return null;
  }
}

/** Latest runs for a user (for the dashboard / daily report list). */
export async function getLatestRuns(userId: string, limit = 20): Promise<TestRun[]> {
  const db = await getDb();
  return db.select().from(schema.testRuns).where(eq(schema.testRuns.userId, userId)).orderBy(desc(schema.testRuns.createdAt)).limit(limit);
}

/** One run with its sub-tests, for the report detail view. */
export async function getRunWithResults(runId: string): Promise<{ run: TestRun; results: TestResult[] } | null> {
  const db = await getDb();
  const run = (await db.select().from(schema.testRuns).where(eq(schema.testRuns.id, runId)).limit(1))[0];
  if (!run) return null;
  const results = await db.select().from(schema.testResults).where(eq(schema.testResults.runId, runId));
  return { run, results };
}
