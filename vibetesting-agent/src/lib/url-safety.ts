/**
 * Block SSRF / internal targets before any scan runs (Worker + OVH agent).
 * Only public http(s) destinations allowed for black-box scans.
 */

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata',
  'kubernetes.default',
  'kubernetes.default.svc',
]);

const BLOCKED_SUFFIXES = ['.local', '.localhost', '.internal', '.lan', '.home', '.corp'];

export type UrlSafetyResult =
  | { ok: true; url: string; hostname: string }
  | { ok: false; reason: string };

function isPrivateIpv4(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b, c, d] = m.slice(1).map(Number);
  if ([a, b, c, d].some((n) => n > 255)) return false;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10/8
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local / cloud metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
  if (a === 192 && b === 168) return true; // 192.168/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT / Tailscale-ish 100.64/10
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmark
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateIpv6(ip: string): boolean {
  const x = ip.toLowerCase();
  if (x === '::' || x === '::1') return true;
  if (x.startsWith('fc') || x.startsWith('fd')) return true; // unique local
  if (x.startsWith('fe80')) return true; // link-local
  if (x.startsWith('ff')) return true; // multicast
  // IPv4-mapped :ffff:x.x.x.x
  const mapped = x.match(/:ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIpv4(mapped[1]);
  return false;
}

function isBlockedIp(ip: string): boolean {
  if (ip.includes(':')) return isPrivateIpv6(ip);
  return isPrivateIpv4(ip);
}

/**
 * Validate user-supplied scan target. Does not resolve DNS (agent should re-check after resolve).
 */
export function assertSafeScanUrl(input: string): UrlSafetyResult {
  let raw = (input || '').trim();
  if (!raw) return { ok: false, reason: 'URL is required' };
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;

  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, reason: 'Invalid URL' };
  }

  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return { ok: false, reason: 'Only http and https URLs are allowed' };
  }
  if (u.username || u.password) {
    return { ok: false, reason: 'URLs with embedded credentials are not allowed' };
  }

  const hostname = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!hostname) return { ok: false, reason: 'Hostname required' };

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    return { ok: false, reason: `Hostname blocked: ${hostname}` };
  }
  if (BLOCKED_SUFFIXES.some((s) => hostname.endsWith(s))) {
    return { ok: false, reason: `Hostname suffix blocked: ${hostname}` };
  }

  // Literal IP in hostname
  if (isBlockedIp(hostname)) {
    return { ok: false, reason: `Private or reserved address not allowed: ${hostname}` };
  }

  // Note: do NOT block vibetestingagent.com / *.workers.dev — those are normal public
  // scan targets (dogfood + customer apps on Workers). SSRF is handled via private IP /
  // metadata / localhost rules above (and DNS re-check on the OVH agent).

  return { ok: true, url: u.toString(), hostname };
}

/**
 * After DNS resolve, reject if any A/AAAA is private (agent-side).
 */
export function assertResolvedPublic(ips: string[]): { ok: true } | { ok: false; reason: string } {
  if (!ips.length) return { ok: false, reason: 'DNS returned no addresses' };
  for (const ip of ips) {
    if (isBlockedIp(ip)) {
      return { ok: false, reason: `Resolved to private/reserved address: ${ip}` };
    }
  }
  return { ok: true };
}
