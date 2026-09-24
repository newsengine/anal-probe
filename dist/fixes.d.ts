import type { Finding } from './types.js';
/** The security headers a scan says are missing/weak, as concrete `Name: value` lines (deduped, ordered). */
export declare function missingHeaderLines(findings: Finding[]): string[];
/**
 * Render a fix pack: a consolidated security-headers block (when relevant) plus a per-finding checklist
 * (VTA number, severity, what/why, and the one-line fix), grouped by severity. PR-ready markdown.
 */
export declare function renderFixPack(findings: Finding[], opts: {
    target: string;
    projectName?: string;
}): string;
