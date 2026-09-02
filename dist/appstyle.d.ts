import type { Finding, ScanContext, Severity } from './types.js';
export type AppStyleKey = 'ecommerce' | 'saas-dashboard' | 'marketing-site' | 'blog-cms' | 'auth-portal' | 'api-backend' | 'marketplace' | 'booking' | 'fintech' | 'healthcare' | 'social-community' | 'chat-messaging' | 'file-sharing' | 'admin-panel' | 'docs-site' | 'job-board' | 'real-estate' | 'education-lms' | 'crm' | 'support-helpdesk';
export interface AppStyleSignal {
    key: AppStyleKey;
    label: string;
    score: number;
    strong: boolean;
    why: string[];
}
/** Pre-computed, cheap views of the homepage every detector/rule shares. */
export interface AppContext {
    html: string;
    hay: string;
    text: string;
    path: string;
    jsonLdTypes: string[];
    headers: Headers;
    isHttps: boolean;
}
/** Detect business archetype(s) from the homepage. Returns scored signals, highest first. */
export declare function detectAppStyles(ctx: ScanContext): AppStyleSignal[];
/**
 * appstyle category: detect the business archetype, then run that type's rule pack. Only archetypes at
 * or above the confidence threshold run (top 2 max), so a marketing site isn't scanned as a bank.
 */
export declare function appStyleChecks(ctx: ScanContext): Promise<Finding[]>;
export interface AppStyleRuleSpec {
    id: string;
    key: AppStyleKey;
    label: string;
    title: string;
    severity: Severity;
    description: string;
}
export declare function appStyleRuleSpecs(): AppStyleRuleSpec[];
export declare const APP_STYLE_KEYS: AppStyleKey[];
