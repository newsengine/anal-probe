import type { Category, Finding, ScanContext, ScanOptions, Severity } from './types.js';
export type { Category, Finding, ScanContext, ScanOptions, Severity };
export type ProbeOptions = ScanOptions;
export declare const ALL_CATEGORIES: Category[];
/** Add https:// when the user typed a bare domain, so `anal-probe example.com` just works. */
export declare function normalizeUrl(input: string): string;
/** Run the comprehensive scan. Returns every finding across the selected categories. */
export declare function probe(baseUrl: string, opts?: ScanOptions): Promise<Finding[]>;
/** Alias — reads better for the full-app use case. */
export declare const scan: typeof probe;
export declare function summarize(findings: Finding[]): {
    passed: number;
    failed: number;
    failHigh: number;
    failMedium: number;
    failLow: number;
    byCategory: Record<string, {
        passed: number;
        failed: number;
    }>;
};
