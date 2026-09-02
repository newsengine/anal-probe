import type { Finding, ScanContext } from './types.js';
/** Pull same-origin /api/* (and /rest//v1/) paths referenced anywhere in the homepage HTML. */
export declare function discoverApiRoutes(ctx: ScanContext): string[];
/**
 * exposure category: unauthenticated API-route probe.
 * - GET every candidate route WITHOUT auth headers → flag 200 + JSON data + no auth challenge.
 * - (opt-in `apiWrite`) POST a benign body to write-suggestive routes → flag any 2xx.
 * All GET-only by default; writes require the flag and skip destructive verbs.
 */
export declare function apiExposureFindings(ctx: ScanContext): Promise<Finding[]>;
/**
 * security category: API-response nuances.
 * - api.cors    (default on): a discovered route reflects an arbitrary Origin with credentials.
 * - api.rate-limit (opt-in `rateLimitScan`): burst expensive routes; expect a 429.
 * - xss.reflected  (opt-in `reflectedXss`): a benign marker on a public query param reflects unencoded.
 */
export declare function apiSecurityFindings(ctx: ScanContext): Promise<Finding[]>;
export declare function reflectedXssFindings(ctx: ScanContext): Promise<Finding[]>;
