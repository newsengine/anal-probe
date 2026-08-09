import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { handleWorkOSCallback } from '@/lib/workos';
import { config } from '@/lib/config';

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get('code');
  const state = req.nextUrl.searchParams.get('state');
  const jar = await cookies();
  const expected = jar.get('oauth_state')?.value;
  jar.delete('oauth_state');

  if (!code) {
    return NextResponse.redirect(new URL('/login?error=workos_code', config.appUrl));
  }
  if (state && expected && state !== expected) {
    return NextResponse.redirect(new URL('/login?error=oauth_state', config.appUrl));
  }

  try {
    await handleWorkOSCallback(code);
    return NextResponse.redirect(new URL('/dashboard', config.appUrl));
  } catch (e) {
    console.error(e);
    return NextResponse.redirect(new URL('/login?error=workos_auth', config.appUrl));
  }
}
