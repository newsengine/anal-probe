import type { Finding } from './types.js';
export interface StandardRefs {
    asvs?: string[];
    owasp?: string;
    wstg?: string[];
}
/** Standards mapped to a finding id (longest matching prefix). */
export declare function refsFor(findingId: string): StandardRefs;
export interface AsvsReq {
    id: string;
    text: string;
    checkPrefix?: string;
    cleanSignal?: string;
    covered: boolean;
}
export declare const ASVS_L1: AsvsReq[];
export type AsvsStatus = 'pass' | 'fail' | 'not-observed' | 'not-covered';
export interface AsvsResult extends AsvsReq {
    status: AsvsStatus;
}
/** Grade each ASVS L1 requirement from a scan's findings. */
export declare function asvsCoverage(findings: Finding[]): AsvsResult[];
/** Which OWASP Top 10 categories the scan touched (from failing findings). */
export declare function owaspTop10Hit(findings: Finding[]): Record<string, number>;
export declare const OWASP_TOP10_NAMES: Record<string, string>;
