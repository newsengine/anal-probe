import type { Finding, ScanContext } from './types.js';
/** Fingerprint the edge/host from response headers. Pure/testable. */
export declare function identifyEdge(headers: Headers | Record<string, string>): {
    providers: string[];
    behindCdn: boolean;
};
export declare function hostChecks(ctx: ScanContext): Promise<Finding[]>;
