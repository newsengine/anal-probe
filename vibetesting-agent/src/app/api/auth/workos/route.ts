import { NextResponse } from 'next/server';
import { randomBytes } from 'node:crypto';
import { cookies } from 'next/headers';
import { getAuthorizationUrl, workosEnabled } from '@/lib/workos';
import { config } from '@/lib/config';

export async function GET() {
  if (!workosEnabled()) {
    return NextResponse.redirect(new URL('/api/auth/github', config.appUrl));
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
  const url = getAuthorizationUrl(state);
  return NextResponse.redirect(url);
}
