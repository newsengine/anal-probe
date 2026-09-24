import type { Finding, ScanContext, Severity } from './types.js';
/** ATLAS technique reference table — id → {name, tactic}. Cited by findings for matrix mapping. */
export declare const ATLAS_TECHNIQUES: Record<string, {
    name: string;
    tactic: string;
}>;
/** Detect whether the app exposes an AI/LLM surface at all (homepage markers + /api/(chat|ai|…) refs). */
export declare function detectAiSurface(ctx: ScanContext): {
    present: boolean;
    why: string[];
    endpoints: string[];
};
/**
 * atlas category: AI-attack-surface checks, run only when an AI surface is detected. Findings cite the
 * ATLAS technique id in their detail. Loud probes (prompt injection, cost burst) require opt-in flags.
 */
export declare function atlasChecks(ctx: ScanContext): Promise<Finding[]>;
export interface AtlasCheckSpec {
    id: string;
    title: string;
    severity: Severity;
    atlas: string[];
    optIn?: boolean;
    dynamic?: boolean;
    description: string;
}
export declare function atlasCheckSpecs(): AtlasCheckSpec[];
