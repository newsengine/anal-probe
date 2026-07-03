import type { Finding } from './types.js';
export interface ObservationGroup {
    heading: string;
    points: string[];
}
export declare function renderReport(url: string, findings: Finding[], opts?: {
    generatedAt?: string;
    observations?: ObservationGroup[];
}): string;
