import { randomBytes } from 'node:crypto';

export function id(prefix = ''): string {
  const body = randomBytes(12).toString('hex');
  return prefix ? `${prefix}_${body}` : body;
}

export function token(bytes = 24): string {
  return randomBytes(bytes).toString('base64url');
}

export function apiKeyPlain(): { plain: string; prefix: string } {
  const body = randomBytes(24).toString('base64url');
  const plain = `sk_live_${body}`;
  return { plain, prefix: plain.slice(0, 14) + '…' };
}
