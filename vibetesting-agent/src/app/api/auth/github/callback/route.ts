import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { config } from '@/lib/config';
import { createSession, upsertGithubUser } from '@/lib/auth';
import { audit } from '@/lib/audit';

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get('code');
  const state = req.nextUrl.searchParams.get('state');
  const jar = await cookies();
  const expected = jar.get('oauth_state')?.value;
  jar.delete('oauth_state');

  if (!code || !state || !expected || state !== expected) {
    return NextResponse.redirect(new URL('/login?error=oauth_state', config.appUrl));
  }

  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: config.github.clientId,
      client_secret: config.github.clientSecret,
      code,
      redirect_uri: `${config.appUrl}/api/auth/github/callback`,
    }),
  });
  const tokenData = (await tokenRes.json()) as { access_token?: string; error?: string };
  if (!tokenData.access_token) {
    return NextResponse.redirect(new URL('/login?error=oauth_token', config.appUrl));
  }

  const userRes = await fetch('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'VibeTesting Agent',
    },
  });
  const profile = (await userRes.json()) as {
    id: number;
    login: string;
    name?: string;
    email?: string;
    avatar_url?: string;
  };

  let email = profile.email;
  if (!email) {
    const emailsRes = await fetch('https://api.github.com/user/emails', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'VibeTesting Agent',
      },
    });
    if (emailsRes.ok) {
      const emails = (await emailsRes.json()) as { email: string; primary: boolean; verified: boolean }[];
      email = emails.find((e) => e.primary && e.verified)?.email || emails[0]?.email;
    }
  }

  const user = await upsertGithubUser({ ...profile, email });
  await createSession(user.id);
  await audit('auth.login', { userId: user.id, detail: { provider: 'github' } });
  return NextResponse.redirect(new URL('/dashboard', config.appUrl));
}
