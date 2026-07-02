import type { Finding } from './types.js';
export declare function browseChecks(startUrl: string, opts?: {
    pages?: number;
    timeoutMs?: number;
    headers?: Record<string, string>;
}): Promise<Finding[]>;
