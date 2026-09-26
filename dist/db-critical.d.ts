import type { Finding, Severity } from './types.js';
export type DbCriticalRole = 'editor' | 'superadmin' | 'user';
export interface DbCriticalSpec {
    id: string;
    title: string;
    severity: Severity;
    description: string;
    /** authenticated = needs role env; white-box = fixture/gated; probe = black-box safe without auth */
    cls: 'authenticated' | 'white-box' | 'probe';
}
/** Catalog specs for docs/CHECKS.md (appended by catalog.ts). */
export declare function dbCriticalCheckSpecs(): DbCriticalSpec[];
/** Minimal RFC 6238 TOTP (SHA-1, 30s, 6 digits) — no extra dependency. */
export declare function totpCode(secretBase32: string, nowMs?: number): string;
/** Password-grant a Bearer token. Handles optional TOTP challenge when VTA_TOTP_SECRET is set. */
export declare function obtainAccessToken(role: DbCriticalRole): Promise<{
    token?: string;
    skipReason?: string;
    error?: string;
}>;
/** 1x1 PNG */
export declare const TINY_PNG: Buffer<ArrayBuffer>;
export declare function runDbCritical(targetUrl: string, opts?: {
    timeoutMs?: number;
}): Promise<Finding[]>;
/** Pure helpers exported for unit tests. */
export declare function htmlReflectsXss(body: string, payload: string): boolean;
export declare function profilesDumpDetected(status: number, rows: unknown): boolean;
export declare function assertTimingSafeEqual(a: string, b: string): boolean;
