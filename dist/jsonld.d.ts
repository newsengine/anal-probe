import type { Finding, ScanContext } from './types.js';
export interface JsonLdIssue {
    index: number;
    severity: 'high' | 'medium';
    detail: string;
}
/** Pure + testable: scan a blob of HTML for JSON-LD script-breakout risk. */
export declare function scanJsonLdBreakout(html: string): JsonLdIssue[];
export declare function jsonLdFindings(ctx: ScanContext): Finding[];
