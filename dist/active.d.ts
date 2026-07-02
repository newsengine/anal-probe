import type { Severity } from './types.js';
export interface ServiceInfo {
    name: string;
    severity: Severity;
    note?: string;
}
export declare const SERVICES: Record<number, ServiceInfo>;
export declare const COMMON_PORTS: number[];
export interface PortResult {
    port: number;
    open: boolean;
    service?: ServiceInfo;
    banner?: string;
}
/** One TCP-connect probe. open=true if the handshake completes; grabs an early banner if the service sends one. */
export declare function scanPort(host: string, port: number, timeoutMs?: number): Promise<PortResult>;
/** Bounded-concurrency scan over a port list. */
export declare function scanPorts(host: string, ports: number[], opts?: {
    concurrency?: number;
    timeoutMs?: number;
}): Promise<PortResult[]>;
/** Parse a --ports spec: "common" (default), "all" (1-65535), "top1000", or "22,80,443,6379". */
export declare function parsePorts(spec?: string): number[];
export interface ReconResult {
    host: string;
    ips: string[];
    open: PortResult[];
    scanned: number;
}
/** Resolve the host and scan the given ports. Caller handles the CDN/authorization gate. */
export declare function recon(host: string, ports: number[], opts?: {
    concurrency?: number;
    timeoutMs?: number;
}): Promise<ReconResult>;
