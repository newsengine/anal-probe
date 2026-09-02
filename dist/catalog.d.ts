import type { Category, Severity } from './types.js';
/**
 * How a check reaches its verdict — this is what "not just a black box" means in practice: every check
 * declares whether it merely reads the one homepage response, makes extra safe GETs, sends a crafted/
 * active probe, needs a logged-in session, or is a white-box helper that needs source/tokens/two accounts.
 */
export type CheckClass = 'passive' | 'probe' | 'active' | 'authenticated' | 'white-box';
export interface CheckSpec {
    /** Stable finding id, or — when `dynamic` — the id prefix the engine appends a target to. */
    id: string;
    category: Category | 'testkit';
    /** Short human name for the catalog. */
    title: string;
    /** Typical severity when it fails (some vary at runtime by context). */
    severity: Severity;
    cls: CheckClass;
    /** Needs an explicit flag/option to run at all (off by default). */
    optIn?: boolean;
    /** The id is a family prefix — real findings look like `${id}${target}`. */
    dynamic?: boolean;
    /** Package version the check first shipped in (best-effort). */
    since: string;
    /** One line: what it detects and why it matters. */
    description: string;
}
export declare const CATALOG: CheckSpec[];
/** Exact-match first, then the longest `dynamic` family prefix the id starts with. */
export declare function catalogEntryFor(id: string): CheckSpec | undefined;
/** Every id/family the scanner (non-testkit) is expected to be able to emit. */
export declare function scannerSpecs(): CheckSpec[];
/** Render docs/CHECKS.md from the catalog. Kept deterministic so a drift test can compare byte-for-byte. */
export declare function renderCatalogMarkdown(): string;
