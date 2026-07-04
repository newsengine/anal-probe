import type { Finding, ScanContext } from './types.js';
export declare function scanDomXssSinks(js: string): {
    sink: string;
    snippet: string;
}[];
export declare function domXssFindings(ctx: ScanContext): Finding[];
