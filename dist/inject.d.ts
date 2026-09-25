import type { Finding, ScanContext, Severity } from './types.js';
export interface Probe {
    status: number;
    body: string;
    ms: number;
}
export type Prober = (value: string) => Promise<Probe>;
export interface InjectionHit {
    kind: 'sqli' | 'ssti' | 'cmdi' | 'traversal';
    severity: Severity;
    detail: string;
    evidence: string;
}
export declare function detectSqlError(baseline: Probe, prober: Prober): Promise<InjectionHit | null>;
export declare function detectSqlBoolean(baseline: Probe, prober: Prober): Promise<InjectionHit | null>;
export declare function detectSqlTime(baseline: Probe, prober: Prober): Promise<InjectionHit | null>;
export declare function detectSsti(prober: Prober): Promise<InjectionHit | null>;
export declare function detectCmdTime(baseline: Probe, prober: Prober): Promise<InjectionHit | null>;
export declare function detectTraversal(baseline: Probe, prober: Prober): Promise<InjectionHit | null>;
/** Run every detector against one (baseline, prober); return the hits found. */
export declare function runDetectors(baseline: Probe, prober: Prober): Promise<InjectionHit[]>;
/**
 * Authorized, non-destructive active injection scan. Builds the coverage map, then tests each GET
 * query parameter with the detector suite. Returns [] unless opts.authorizedActive is set.
 */
export declare function activeInjectionScan(ctx: ScanContext): Promise<Finding[]>;
