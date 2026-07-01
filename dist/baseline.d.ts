import type { Finding } from './types.js';
/** Stable identity for a finding across runs. `id` already encodes the check + any per-item suffix
 *  (e.g. `cookie.sid`, `exposed/.env`), so it's the right grain to accept/ignore individually. */
export declare function findingKey(f: Finding): string;
export interface Baseline {
    /** Sorted, de-duplicated keys of findings that were failing when the baseline was written. */
    keys: string[];
    /** Free-form provenance (URL / timestamp) — informational only, not used for matching. */
    createdFor?: string;
}
/** Build a baseline from a scan's failing findings. */
export declare function buildBaseline(findings: Finding[], createdFor?: string): Baseline;
export interface BaselineDiff {
    /** Failing findings NOT present in the baseline — these are what CI should gate on. */
    newFailures: Finding[];
    /** Failing findings that were already accepted in the baseline. */
    baselined: Finding[];
}
/** Partition failing findings into new vs. already-baselined. Passing findings are ignored. */
export declare function applyBaseline(findings: Finding[], baseline: Baseline): BaselineDiff;
