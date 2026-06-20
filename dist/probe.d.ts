export type Severity = 'high' | 'medium' | 'low' | 'info';
export interface Finding {
    id: string;
    title: string;
    severity: Severity;
    pass: boolean;
    detail: string;
}
export interface ProbeOptions {
    /** Paths expected to exist for the security.txt / CORS checks. */
    securityTxtPath?: string;
    /** An API path to test CORS reflection against (should be a CORS-enabled endpoint). */
    corsTestPath?: string;
    /** Treat these missing headers as info (not fail) — e.g. CSP if you only ship Report-Only. */
    allowReportOnlyCsp?: boolean;
    /** Opt-in: a path to burst-test for rate limiting (sends ~25 quick requests; expects a 429). */
    rateLimitPath?: string;
}
export declare function probe(baseUrl: string, opts?: ProbeOptions): Promise<Finding[]>;
export declare function summarize(findings: Finding[]): {
    passed: number;
    failed: number;
    failHigh: number;
    failMedium: number;
};
