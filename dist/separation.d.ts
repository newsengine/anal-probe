import { type TenantVerdict } from './testkit.js';
export interface SeparationAccount {
    label: string;
    tenant: string;
    chromeProfile: string;
}
export interface SeparationConfig {
    origin: string;
    /** Query param carrying the tenant/org id (default tenant_uuid). */
    tenantParam?: string;
    chromeProfilesDir?: string;
    /** App pages to visit so it fires its authenticated API calls (default ['/']). */
    appPaths?: string[];
    owner: SeparationAccount;
    attacker: SeparationAccount;
    /** Tenant-scoped endpoints to test, matched by URL substring. */
    endpoints: {
        name: string;
        match: string;
    }[];
}
export interface SeparationResult {
    name: string;
    verdict: TenantVerdict;
    reason: string;
    statuses: {
        baseline?: number;
        attack?: number;
        control?: number;
    };
}
export declare function runSeparation(cfg: SeparationConfig): Promise<SeparationResult[]>;
