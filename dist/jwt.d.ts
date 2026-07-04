import type { Finding, ScanContext } from './types.js';
export declare function b64urlDecode(seg: string): string;
export interface JwtAnalysis {
    valid: boolean;
    alg?: string;
    header?: Record<string, unknown>;
    claims?: Record<string, unknown>;
    hasExp: boolean;
    expSeconds?: number;
    lifetimeDays?: number;
    sensitiveClaims: string[];
}
export declare function analyzeJwt(token: string): JwtAnalysis;
export declare function jwtFindings(ctx: ScanContext): Finding[];
