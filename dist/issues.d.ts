import type { Finding } from './types.js';
/** A hidden marker embedded in every managed issue body so re-runs can match the same tracking issue. */
export declare function issueKey(target: string, finding: Finding): string;
export declare function markerFor(key: string): string;
export declare function keyFromBody(body: string): string | null;
export interface ExistingIssue {
    number: number;
    state: 'open' | 'closed';
    key: string;
}
export interface IssueSpec {
    key: string;
    title: string;
    body: string;
    labels: string[];
}
export interface IssueActions {
    toOpen: IssueSpec[];
    toUpdate: {
        number: number;
        spec: IssueSpec;
    }[];
    toClose: {
        number: number;
        key: string;
    }[];
}
/**
 * Compute the idempotent open/update/close plan.
 * - a FAILING finding → open (new) or update (existing issue for its key)
 * - an existing OPEN issue whose key no longer maps to a failing finding → close (fixed / no longer seen)
 * Only failing findings produce issues (passes/info are not filed).
 */
export declare function planIssueActions(findings: Finding[], opts: {
    target: string;
    existing?: ExistingIssue[];
}): IssueActions;
/** One-line human summary of a plan (for CLI dry-run output). */
export declare function summarizeActions(a: IssueActions): string;
