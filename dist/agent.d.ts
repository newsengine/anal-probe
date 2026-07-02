import type { Finding, ScanContext } from './types.js';
export declare const AI_CRAWLERS: string[];
/** Visible text an agent would read if it does NOT execute JavaScript (strips script/style/tags/entities). */
export declare function visibleText(html: string): string;
/**
 * Parse robots.txt and return which of `uaList` are blocked from the site root. A UA is "blocked" when
 * the group that applies to it (its own, else the `*` wildcard) contains `Disallow: /`. Groups are the
 * standard robots.txt records: one or more consecutive `User-agent:` lines followed by rules.
 */
export declare function aiCrawlersBlocked(robotsTxt: string, uaList?: string[]): string[];
export interface AgentReadinessInput {
    html: string;
    /** true if /llms.txt is present and looks like text/markdown (not an SPA HTML fallback). */
    hasLlmsTxt: boolean;
    /** robots.txt body ('' if none). */
    robotsTxt: string;
    robotsPresent: boolean;
    /** true if an MCP / ai-plugin manifest is discoverable under /.well-known. */
    hasAgentManifest: boolean;
}
/** Pure grader → deterministic, network-free, fully unit-testable. */
export declare function evaluateAgentReadiness(inp: AgentReadinessInput): Finding[];
/** Gather the inputs (cheap GETs) and grade. */
export declare function agentChecks(ctx: ScanContext): Promise<Finding[]>;
