export type Severity = 'high' | 'medium' | 'low' | 'info';
/** Buckets a vibe coder actually cares about: "is it broken / leaking / unfindable / slow?". */
export type Category = 'security' | 'secrets' | 'exposure' | 'dns' | 'reliability' | 'seo' | 'a11y' | 'performance' | 'agent' | 'framework' | 'components' | 'host' | 'plugins';
export interface Finding {
    id: string;
    category: Category;
    title: string;
    severity: Severity;
    pass: boolean;
    detail: string;
    /** Optional one-line "how to fix" aimed at a non-expert. */
    fix?: string;
}
export interface ScanOptions {
    /** Path expected to hold security.txt (default /.well-known/security.txt). */
    securityTxtPath?: string;
    /** An API path to test CORS reflection against. */
    corsTestPath?: string;
    /** Opt-in: a path to burst-test for rate limiting (sends ~25 quick requests; expects a 429). */
    rateLimitPath?: string;
    /** Treat CSP-Report-Only as a pass (apps mid-rollout). */
    allowReportOnlyCsp?: boolean;
    /** Only run these categories (default: all). */
    only?: Category[];
    /** Skip these categories. */
    skip?: Category[];
    /** Max same-origin links/images/scripts to fetch when checking for breakage (default 25). */
    maxCrawl?: number;
    /** Per-request network timeout in ms (default 10000). Guards against sites that never respond. */
    timeoutMs?: number;
    /** Directory of user JSON plugin templates for the `plugins` category (default ./vibetesting-agent-plugins). */
    pluginsDir?: string;
    /** Extra headers (e.g. Cookie / Authorization) sent ONLY on same-origin requests, so the scan can
     *  reach pages behind login. Never attached to the attack-probe requests (CORS/open-redirect) or any
     *  cross-origin fetch, to avoid leaking your session to a third party. */
    extraHeaders?: Record<string, string>;
}
/** Shared, fetched-once context handed to every check so we hit the homepage a single time. */
export interface ScanContext {
    baseUrl: string;
    origin: string;
    url: URL;
    /** The main document response (null if unreachable). */
    res: Response | null;
    /** The main document HTML (empty string if unreachable / non-HTML). */
    html: string;
    headers: Headers;
    opts: ScanOptions;
    /** Frameworks/platforms fingerprinted from the homepage (populated by the scanner; used by the
     *  `framework` category and available for reporting). */
    stacks?: import('./detect.js').StackSignal[];
}
