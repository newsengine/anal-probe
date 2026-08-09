/**
 * HMAC helpers so OVH agents cannot forge completions without SCAN_AGENT_SECRET.
 * Works on Node and Workers (Web Crypto).
 */

function toBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function b64url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  // btoa available in Workers + Node 22+
  const b64 = btoa(bin);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    toBytes(secret) as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

/** Stable canonical JSON for signing (sorted keys, no whitespace). */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) out[k] = sortKeys(o[k]);
    return out;
  }
  return v;
}

export async function signAgentPayload(secret: string, payload: unknown): Promise<string> {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, toBytes(canonicalJson(payload)) as BufferSource);
  return b64url(sig);
}

export async function verifyAgentPayload(
  secret: string,
  payload: unknown,
  signature: string,
): Promise<boolean> {
  if (!signature || !secret) return false;
  try {
    const expected = await signAgentPayload(secret, payload);
    if (expected.length !== signature.length) return false;
    let out = 0;
    for (let i = 0; i < expected.length; i++) {
      out |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
    }
    return out === 0;
  } catch {
    return false;
  }
}

export function agentAuthBearer(req: Request, secret: string): boolean {
  if (!secret) return false;
  const header = req.headers.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token || token.length !== secret.length) return false;
  let out = 0;
  for (let i = 0; i < token.length; i++) out |= token.charCodeAt(i) ^ secret.charCodeAt(i);
  return out === 0;
}
