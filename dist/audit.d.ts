export interface AuditResult {
    counts: Record<string, number>;
    total: number;
    raw?: unknown;
    error?: string;
}
export declare function runNpmAudit(cwd?: string, prodOnly?: boolean): Promise<AuditResult>;
/** True if the audit has any vuln at or above `level`. */
export declare function failsAtLevel(result: AuditResult, level: string): boolean;
