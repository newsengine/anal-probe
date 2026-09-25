import type { ScanOptions } from './types.js';
export interface FormSpec {
    action: string;
    method: string;
    fields: string[];
}
export interface CoverageMap {
    seed: string;
    origin: string;
    endpoints: string[];
    params: string[];
    forms: FormSpec[];
    apis: string[];
    paramUrls: string[];
    pagesVisited: number;
    capped: boolean;
}
export interface CrawlMapOptions {
    maxPages?: number;
    maxDepth?: number;
    timeoutMs?: number;
    extraHeaders?: ScanOptions['extraHeaders'];
}
/** Parse <form> blocks into {action, method, fields}. Regex-based, tolerant, zero-dep. */
export declare function parseForms(baseUrl: string, htmlText: string): FormSpec[];
/** Bounded, same-origin BFS coverage map. Auth via opts.extraHeaders (sent same-origin only). */
export declare function buildCoverageMap(seed: string, opts?: CrawlMapOptions): Promise<CoverageMap>;
/** One-line human summary of a coverage map. */
export declare function summarizeCoverage(map: CoverageMap): string;
