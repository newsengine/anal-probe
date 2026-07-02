import type { Finding, ScanContext } from './types.js';
/** Registrable apex ("eTLD+1"). Handles common multi-label suffixes (`example.com.au` → itself, not
 *  `com.au`) via a curated suffix set, falling back to the last two labels for ordinary TLDs. */
export declare function apexOf(hostname: string): string;
export interface DnsRecords {
    hostname: string;
    apex: string;
    /** TXT records on the apex (each already joined into one string). */
    apexTxt: string[];
    /** TXT records on _dmarc.<apex>. */
    dmarcTxt: string[];
    /** true if the apex has ≥1 CAA record. */
    hasCaa: boolean;
    /** A CNAME target of `hostname` that fails to resolve (dangling → takeover risk), or null. */
    danglingCnameTarget: string | null;
}
/** Pure grader — deterministic given the gathered records, so it unit-tests without touching the network. */
export declare function evaluateDnsHygiene(r: DnsRecords): Finding[];
/** Gather the DNS records for a host (all lookups fail soft to empty/false). */
export declare function gatherDns(hostname: string): Promise<DnsRecords>;
export declare function dnsChecks(ctx: ScanContext): Promise<Finding[]>;
