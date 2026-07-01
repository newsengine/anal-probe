import type { Finding, ScanContext, Severity } from './types.js';
export interface CspIssue {
    id: string;
    title: string;
    severity: Severity;
    detail: string;
    fix: string;
}
/** Grade a CSP beyond mere presence: the weaknesses that actually let XSS through. Regex-free, zero-dep. */
export declare function lintCsp(policy: string): CspIssue[];
export declare function securityChecks(ctx: ScanContext): Promise<Finding[]>;
export declare function secretChecks(ctx: ScanContext): Promise<Finding[]>;
export declare function exposureChecks(ctx: ScanContext): Promise<Finding[]>;
export declare function reliabilityChecks(ctx: ScanContext): Promise<Finding[]>;
export declare function seoChecks(ctx: ScanContext): Promise<Finding[]>;
export declare function a11yChecks(ctx: ScanContext): Promise<Finding[]>;
export declare function performanceChecks(ctx: ScanContext): Promise<Finding[]>;
