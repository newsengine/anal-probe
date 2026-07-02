/**
 * Days until the served TLS certificate expires (null if it can't be determined). Uses a raw TLS
 * connection because fetch() doesn't expose the peer certificate.
 */
export declare function tlsCertDaysRemaining(host: string, port?: number): Promise<number | null>;
export declare const DEFAULT_TIMEOUT_MS = 10000;
export declare function safeFetch(url: string, init?: RequestInit, timeoutMs?: number): Promise<Response | null>;
/**
 * Fetch text with a hard timeout AND a streaming byte cap: we stop reading once maxBytes have arrived,
 * so a gzip bomb / endless stream can't OOM the process (arrayBuffer() would buffer the whole body first).
 * Returns '' on any failure. Binary responses are decoded lossily — callers only regex over them.
 */
export declare function fetchText(url: string, init?: RequestInit, maxBytes?: number, timeoutMs?: number): Promise<string>;
export declare function headerGet(h: Headers | Record<string, string>, name: string): string | null;
/** Resolve a possibly-relative href against the page origin; null if it can't be parsed. */
export declare function resolveUrl(base: string, href: string): string | null;
export declare function sameOrigin(a: string, b: string): boolean;
export declare function matchAllGroups(html: string, re: RegExp): string[];
export declare const html: {
    title: (h: string) => string;
    hasLang: (h: string) => boolean;
    metaContent: (h: string, name: string) => string | null;
    hasViewport: (h: string) => boolean;
    canonical: (h: string) => string | null;
    scripts: (h: string) => string[];
    links: (h: string) => string[];
    images: (h: string) => {
        src: string;
        hasAlt: boolean;
    }[];
    h1Count: (h: string) => number;
    inputsNeedingLabel: (h: string) => number;
    labelCount: (h: string) => number;
    insecureRefs: (h: string) => string[];
};
export interface SecretRule {
    id: string;
    name: string;
    severity: 'high' | 'medium' | 'low';
    re: RegExp;
    /** Optional extra confirmation to cut false positives. */
    confirm?: (match: string, blob: string) => boolean;
}
export declare const SECRET_RULES: SecretRule[];
export interface SecretHit {
    ruleId: string;
    name: string;
    severity: 'high' | 'medium' | 'low';
    sample: string;
}
export declare function scanSecrets(blob: string): SecretHit[];
