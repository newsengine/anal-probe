import type { Finding } from './types.js';
export declare function renderReport(url: string, findings: Finding[], opts?: {
    generatedAt?: string;
}): string;
