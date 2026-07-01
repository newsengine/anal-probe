import type { Finding } from './types.js';
export interface SarifOptions {
    /** Tool version string (defaults to a stable placeholder). */
    version?: string;
    /** The scanned URL, recorded on the run for context. */
    url?: string;
}
export declare function toSarif(findings: Finding[], opts?: SarifOptions): unknown;
