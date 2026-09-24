import type { Finding, ScanContext, Severity } from './types.js';
export interface ServerCve {
    product: RegExp;
    cve: string;
    severity: Severity;
    affected: (v: string) => boolean;
    note: string;
    fix: string;
}
export declare const SERVER_CVES: ServerCve[];
/** Product + version pairs advertised in Server / X-Powered-By headers (e.g. "nginx/1.18.0", "Apache/2.4.49 (Ubuntu)"). */
export declare function parseServerBanners(ctx: ScanContext): {
    product: string;
    version: string;
    raw: string;
}[];
/** category 'components': flag any disclosed server/runtime version that matches a curated CVE. */
export declare function serverCveFindings(ctx: ScanContext): Finding[];
