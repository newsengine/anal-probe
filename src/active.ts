// src/active.ts
// ACTIVE host reconnaissance — the aggressive, opt-in mode. TCP-connect port scanning + banner grabbing
// + dangerous-service flagging. This sends real connections to the target, so it is OFF by default and
// gated behind an explicit authorization flag (`recon --yes-i-am-authorized`) and a CDN check (scanning a
// CDN edge means scanning a third party — refused unless --force).
//
// DELIBERATE LIMITS (this is a scanner, not an attack tool): recon ONLY. No exploitation, no DoS/flooding
// (bounded concurrency + timeouts, one connection per port), no credential brute-forcing. For exploit or
// CVE validation, point nmap/nuclei/testssl.sh at the origin.

import net from 'node:net';
import { promises as dns } from 'node:dns';
import type { Severity } from './types.js';

export interface ServiceInfo { name: string; severity: Severity; note?: string }

// Ports whose exposure is itself a finding (data stores, admin/RCE surfaces, cleartext protocols).
export const SERVICES: Record<number, ServiceInfo> = {
  21: { name: 'FTP', severity: 'medium', note: 'often cleartext credentials' },
  22: { name: 'SSH', severity: 'low', note: 'ensure key-only auth + fail2ban' },
  23: { name: 'Telnet', severity: 'high', note: 'cleartext — should never be public' },
  25: { name: 'SMTP', severity: 'low' },
  135: { name: 'MSRPC', severity: 'medium' },
  139: { name: 'NetBIOS', severity: 'medium' },
  445: { name: 'SMB', severity: 'high', note: 'SMB should never be internet-facing (EternalBlue etc.)' },
  1433: { name: 'MSSQL', severity: 'medium' },
  1521: { name: 'Oracle DB', severity: 'medium' },
  2375: { name: 'Docker API (plaintext)', severity: 'high', note: 'root-equivalent RCE if unauthenticated' },
  2376: { name: 'Docker API (TLS)', severity: 'medium' },
  3306: { name: 'MySQL', severity: 'medium', note: 'DB should not be publicly reachable' },
  3389: { name: 'RDP', severity: 'medium', note: 'brute-force / BlueKeep target' },
  5432: { name: 'PostgreSQL', severity: 'medium', note: 'DB should not be publicly reachable' },
  5601: { name: 'Kibana', severity: 'medium' },
  5900: { name: 'VNC', severity: 'high', note: 'remote desktop — often weak/no auth' },
  5984: { name: 'CouchDB', severity: 'high' },
  6379: { name: 'Redis', severity: 'high', note: 'frequently unauthenticated → data access / RCE' },
  7001: { name: 'WebLogic', severity: 'high', note: 'repeated critical RCE CVEs' },
  8080: { name: 'HTTP-alt', severity: 'info' },
  8443: { name: 'HTTPS-alt', severity: 'info' },
  8888: { name: 'HTTP-alt/Jupyter', severity: 'low' },
  9000: { name: 'app (PHP-FPM/SonarQube/Portainer)', severity: 'low' },
  9092: { name: 'Kafka', severity: 'medium' },
  9200: { name: 'Elasticsearch', severity: 'high', note: 'often unauthenticated → full index access' },
  9300: { name: 'Elasticsearch transport', severity: 'high' },
  11211: { name: 'Memcached', severity: 'high', note: 'unauth + UDP amplification' },
  15672: { name: 'RabbitMQ mgmt', severity: 'medium' },
  27017: { name: 'MongoDB', severity: 'high', note: 'historically unauthenticated' },
  27018: { name: 'MongoDB shard', severity: 'high' },
};
// Web ports worth noting even though they're "expected".
const WEB_PORTS = [80, 443, 3000, 5000, 8000];
export const COMMON_PORTS = [...new Set([...Object.keys(SERVICES).map(Number), ...WEB_PORTS])].sort((a, b) => a - b);

export interface PortResult { port: number; open: boolean; service?: ServiceInfo; banner?: string }

/** One TCP-connect probe. open=true if the handshake completes; grabs an early banner if the service sends one. */
export function scanPort(host: string, port: number, timeoutMs = 2500): Promise<PortResult> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let banner = '';
    let connected = false;
    let settled = false;
    const done = (open: boolean) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve({ port, open, service: SERVICES[port], banner: banner.replace(/[^\x20-\x7e]/g, ' ').trim().slice(0, 120) || undefined });
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => { connected = true; sock.setTimeout(700); }); // short window to catch a banner
    sock.on('data', (d) => { banner += d.toString('latin1'); if (banner.length > 200) done(true); });
    sock.on('timeout', () => done(connected)); // connected but silent = open; never connected = filtered/closed
    // A banner-then-disconnect service (SSH/FTP/SMTP often) closes after sending — resolve on close/end,
    // else the idle-timeout never fires on the already-closed socket and the scan would hang.
    sock.on('close', () => done(connected));
    sock.on('error', () => done(false));
    sock.connect(port, host);
  });
}

/** Bounded-concurrency scan over a port list. */
export async function scanPorts(host: string, ports: number[], opts: { concurrency?: number; timeoutMs?: number } = {}): Promise<PortResult[]> {
  const concurrency = Math.min(opts.concurrency ?? 100, 500);
  const results: PortResult[] = [];
  let i = 0;
  async function worker() {
    while (i < ports.length) {
      const port = ports[i++];
      const r = await scanPort(host, port, opts.timeoutMs);
      if (r.open) results.push(r);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, worker));
  return results.sort((a, b) => a.port - b.port);
}

/** Parse a --ports spec: "common" (default), "all" (1-65535), "top1000", or "22,80,443,6379". */
export function parsePorts(spec?: string): number[] {
  if (!spec || spec === 'common') return COMMON_PORTS;
  if (spec === 'all') return Array.from({ length: 65535 }, (_, n) => n + 1);
  if (spec === 'top1000') return Array.from({ length: 1000 }, (_, n) => n + 1);
  return spec.split(',').map((s) => Number(s.trim())).filter((n) => Number.isInteger(n) && n > 0 && n <= 65535);
}

export interface ReconResult {
  host: string;
  ips: string[];
  open: PortResult[];
  scanned: number;
}

/** Resolve the host and scan the given ports. Caller handles the CDN/authorization gate. */
export async function recon(host: string, ports: number[], opts: { concurrency?: number; timeoutMs?: number } = {}): Promise<ReconResult> {
  const ips = await dns.resolve4(host).catch(() => [] as string[]);
  const open = await scanPorts(host, ports, opts);
  return { host, ips, open, scanned: ports.length };
}
