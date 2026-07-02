export interface CveHit {
    id: string;
    summary: string;
    severity?: string;
}
/** Pure parser for an NVD 2.0 API response — testable without the network. */
export declare function parseNvd(data: any, max?: number): CveHit[];
/**
 * Look up CVEs associated with `product version` via NVD keyword search. Fails soft to []. NVD rate-limits
 * to ~5 requests / 30s without a key, so callers should query sequentially and sparingly.
 */
export declare function lookupCves(product: string, version: string, opts?: {
    max?: number;
    timeoutMs?: number;
}): Promise<CveHit[]>;
