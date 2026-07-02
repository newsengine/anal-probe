import type { Finding } from './types.js';
export interface StandardRefs {
    asvs?: string[];
    owasp?: string;
    wstg?: string[];
    cwe?: string[];
    apiTop10?: string;
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
export declare const OWASP_API_TOP10_NAMES: Record<string, string>;
/** OWASP API Security Top 10 (2023) categories hit by failing findings. */
export declare function apiTop10Hit(findings: Finding[]): Record<string, number>;
/** Distinct CWE ids across failing findings. */
export declare function cwesHit(findings: Finding[]): string[];
/** Mozilla-Observatory-style A+–F grade from failing security/exposure/secrets findings. */
export declare function securityGrade(findings: Finding[]): {
    grade: string;
    score: number;
};
/** SSL-Labs-style A+–F TLS grade from the tls.* findings. */
export declare function tlsGrade(findings: Finding[]): string;
