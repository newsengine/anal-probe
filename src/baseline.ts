// src/baseline.ts
// Baseline / diff mode: record today's failing findings to a committed file, then on later runs only
// fail CI on findings that AREN'T in the baseline. This is what makes the scanner adoptable on a
// legacy app — you snapshot the current debt once and gate on regressions from then on.

import type { Finding } from './types.js';

/** Stable identity for a finding across runs. `id` already encodes the check + any per-item suffix
 *  (e.g. `cookie.sid`, `exposed/.env`), so it's the right grain to accept/ignore individually. */
export function findingKey(f: Finding): string {
  return f.id;
}

export interface Baseline {
  /** Sorted, de-duplicated keys of findings that were failing when the baseline was written. */
  keys: string[];
  /** Free-form provenance (URL / timestamp) — informational only, not used for matching. */
  createdFor?: string;
}

/** Build a baseline from a scan's failing findings. */
export function buildBaseline(findings: Finding[], createdFor?: string): Baseline {
  const keys = [...new Set(findings.filter((f) => !f.pass).map(findingKey))].sort();
  return createdFor ? { keys, createdFor } : { keys };
}

export interface BaselineDiff {
  /** Failing findings NOT present in the baseline — these are what CI should gate on. */
  newFailures: Finding[];
  /** Failing findings that were already accepted in the baseline. */
  baselined: Finding[];
}

/** Partition failing findings into new vs. already-baselined. Passing findings are ignored. */
export function applyBaseline(findings: Finding[], baseline: Baseline): BaselineDiff {
  const accepted = new Set(baseline.keys);
  const newFailures: Finding[] = [];
  const baselined: Finding[] = [];
  for (const f of findings) {
    if (f.pass) continue;
    (accepted.has(findingKey(f)) ? baselined : newFailures).push(f);
  }
  return { newFailures, baselined };
}
