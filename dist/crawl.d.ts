import type { Finding } from './types.js';
export interface CrawlOptions {
    maxPages?: number;
    startPaths?: string[];
    /** Reuse a logged-in Chrome profile (via browser-auth). */
    chromeProfile?: string;
    profilesDir?: string;
    /** Or authenticate with a raw Cookie header. */
    cookie?: string;
    timeoutMs?: number;
}
export declare function crawlAudit(startUrl: string, opts?: CrawlOptions): Promise<Finding[]>;
