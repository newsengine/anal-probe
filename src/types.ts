// src/types.ts
// Shared types for the comprehensive black-box scan. Every check returns Finding[]; the CLI groups
// them by category and turns the worst severities into an exit code so CI gates on real problems.

export type Severity = 'high' | 'medium' | 'low' | 'info';

/** Buckets a vibe coder actually cares about: "is it broken / leaking / unfindable / slow?". */
export type Category =
  | 'security'     // headers, TLS, CORS, cookies
  | 'secrets'      // API keys / private keys / source leaked to the browser
  | 'exposure'     // .env / .git / config / debug endpoints reachable
  | 'reliability'  // broken links/images, 500s, stack-trace leaks, mixed content
  | 'seo'          // title/description/canonical/robots/sitemap
  | 'a11y'         // lang, alt text, labels, viewport
  | 'performance'; // compression, caching, page weight

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
  /** Treat CSP-Report-Only as a pass (apps mid-rollout). */
  allowReportOnlyCsp?: boolean;
  /** Only run these categories (default: all). */
  only?: Category[];
  /** Skip these categories. */
  skip?: Category[];
  /** Max same-origin links/images/scripts to fetch when checking for breakage (default 25). */
  maxCrawl?: number;
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
}
