import type { Finding } from './types.js';
export interface AgentReportOptions {
    url: string;
    projectName?: string;
    generatedAt?: string;
    /** Extra caveats (e.g. embeddable widget note). */
    caveats?: string[];
    /** Include passing checks summary at the end. */
    includePassed?: boolean;
}
/**
 * Render a prioritized agent fix / security-review markdown document.
 * Matches the structure used in reports/sparkle-findings-for-agent.md.
 */
export declare function renderAgentReport(findings: Finding[], opts: AgentReportOptions): string;
/** One-finding clipboard prompt for Cursor/Claude. */
export declare function renderFindingPrompt(url: string, f: Finding): string;
