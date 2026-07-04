import type { Finding, ScanContext, Severity } from './types.js';
export declare function parseVersion(v: string): number[];
export declare function versionLt(a: string, b: string): boolean;
interface Vuln {
    below: string;
    severity: Severity;
    ref: string;
    note: string;
}
export declare const VULN_DB: Record<string, Vuln[]>;
export interface DetectedComponent {
    name: string;
    version: string;
    evidence: string;
}
export declare function detectComponents(htmlText: string, baseUrl: string): DetectedComponent[];
export declare function matchVulnerabilities(c: DetectedComponent): Vuln | null;
export declare function componentChecks(ctx: ScanContext): Promise<Finding[]>;
export {};
