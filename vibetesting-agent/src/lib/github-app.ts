/**
 * GitHub App helpers: check runs, PR comments, webhook verification.
 * Works when GITHUB_APP_* env vars are set; otherwise no-ops gracefully.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { config } from './config';

export function verifyGithubWebhookSignature(rawBody: string, signature: string | null): boolean {
  const secret = config.github.appWebhookSecret;
  if (!secret) return config.isDev; // allow in dev without secret
  if (!signature?.startsWith('sha256=')) return false;
  const expected = 'sha256=' + createHmac('sha256', secret).update(rawBody).digest('hex');
  try {
    return timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  } catch {
    return false;
  }
}

export async function postCheckRun(opts: {
  installationId: string;
  owner: string;
  repo: string;
  headSha: string;
  name?: string;
  conclusion: 'success' | 'failure' | 'neutral';
  title: string;
  summary: string;
  detailsUrl?: string;
}): Promise<void> {
  const token = await installationToken(opts.installationId);
  if (!token) return;
  await fetch(`https://api.github.com/repos/${opts.owner}/${opts.repo}/check-runs`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'VibeTesting Agent',
    },
    body: JSON.stringify({
      name: opts.name || 'VibeTesting Agent',
      head_sha: opts.headSha,
      status: 'completed',
      conclusion: opts.conclusion,
      details_url: opts.detailsUrl,
      output: { title: opts.title, summary: opts.summary },
    }),
  });
}

export async function postPrComment(opts: {
  installationId: string;
  owner: string;
  repo: string;
  issueNumber: number;
  body: string;
}): Promise<void> {
  const token = await installationToken(opts.installationId);
  if (!token) return;
  await fetch(`https://api.github.com/repos/${opts.owner}/${opts.repo}/issues/${opts.issueNumber}/comments`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'VibeTesting Agent',
    },
    body: JSON.stringify({ body: opts.body }),
  });
}

async function installationToken(installationId: string): Promise<string | null> {
  if (!config.github.appId || !config.github.appPrivateKey) return null;
  try {
    const jwt = await appJwt();
    const res = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'VibeTesting Agent',
      },
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { token?: string };
    return data.token || null;
  } catch {
    return null;
  }
}

async function appJwt(): Promise<string> {
  const { SignJWT, importPKCS8 } = await import('jose');
  const key = await importPKCS8(config.github.appPrivateKey, 'RS256');
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt(now - 60)
    .setExpirationTime(now + 9 * 60)
    .setIssuer(config.github.appId)
    .sign(key);
}

export function policyConclusion(
  policy: string,
  newHighs: number,
  newMediums: number,
): 'success' | 'failure' | 'neutral' {
  if (policy === 'chill') return newHighs + newMediums > 0 ? 'neutral' : 'success';
  if (policy === 'ship') return newHighs > 0 ? 'failure' : 'success';
  // client + launch
  return newHighs + newMediums > 0 ? 'failure' : 'success';
}
