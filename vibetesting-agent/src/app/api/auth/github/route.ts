import { NextResponse } from 'next/server';
import { config } from '@/lib/config';
import { randomBytes } from 'node:crypto';
import { cookies } from 'next/headers';

export async function GET() {
  if (!config.github.clientId) {
    // Dev login fallback when GitHub OAuth is not configured
    return NextResponse.redirect(new URL('/api/auth/dev-login', config.appUrl));
  }
  const state = randomBytes(16).toString('hex');
  const jar = await cookies();
  jar.set('oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 600,
  });
  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', config.github.clientId);
  url.searchParams.set('redirect_uri', `${config.appUrl}/api/auth/github/callback`);
  url.searchParams.set('scope', 'read:user user:email');
  url.searchParams.set('state', state);
  return NextResponse.redirect(url.toString());
}
