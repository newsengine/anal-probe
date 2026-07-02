export interface FileConfig {
    only?: string[];
    skip?: string[];
    failOn?: 'high' | 'medium' | 'any';
    corsPath?: string;
    rateLimitPath?: string;
    timeoutMs?: number;
    maxCrawl?: number;
    crawl?: number;
    allowReportOnlyCsp?: boolean;
    quiet?: boolean;
}
/**
 * Load config from an explicit path or the default `.analproberc.json` in cwd. A missing DEFAULT file is
 * fine (returns {}); a missing/invalid EXPLICIT path is an error the caller should surface.
 */
export declare function loadConfig(explicitPath?: string): {
    config: FileConfig;
    error?: string;
};
