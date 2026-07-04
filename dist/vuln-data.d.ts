export type VulnSeverity = 'high' | 'medium' | 'low';
export interface VulnEntry {
    below: string;
    severity: VulnSeverity;
    ref: string;
    note: string;
}
export declare const VULN_DATA: Record<string, VulnEntry[]>;
export declare const VULN_DATA_META: {
    generatedAt: string;
    source: string;
    count: number;
};
