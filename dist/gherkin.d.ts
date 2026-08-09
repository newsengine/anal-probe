import type { Finding } from './types.js';
export interface GherkinOptions {
    url: string;
    projectName?: string;
    /** Only failing findings (default true). */
    failuresOnly?: boolean;
    /** Tag scenarios with @security @high etc. */
    tags?: boolean;
}
/**
 * Single multi-scenario feature file covering all (failing) findings.
 */
export declare function renderGherkinFeature(findings: Finding[], opts: GherkinOptions): string;
/**
 * One file per finding under features/security/ — good for PRs that fix one issue.
 */
export declare function renderGherkinFiles(findings: Finding[], opts: GherkinOptions): {
    path: string;
    content: string;
}[];
/**
 * Minimal step-definition stub (JavaScript) that shells to vibetesting-agent --json.
 * Drop into features/support/vibetesting-agent.steps.mjs for cucumber-js.
 */
export declare function renderGherkinStepStub(): string;
