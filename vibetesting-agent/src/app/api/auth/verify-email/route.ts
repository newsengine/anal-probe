/**
 * Click-to-verify inbox control (from ownership email).
 * GET /api/auth/verify-email?token=…
 */
import { NextResponse } from 'next/server';
import { confirmInboxVerification } from '@/lib/ownership';
import { createSession } from '@/lib/auth';
import { config } from '@/lib/config';

export async function GET(req: Request) {
  const url = new URL(req.url);
  const token = url.searchParams.get('token') || '';
  const user = await confirmInboxVerification(token);

  if (!user) {
    return NextResponse.redirect(
      `${config.appUrl}/login?error=${encodeURIComponent('Email verification link invalid or expired')}`,
    );
  }

  // Ensure they're signed in after clicking the link
  await createSession(user.id);

  return NextResponse.redirect(
    `${config.appUrl}/dashboard/projects?email_verified=1`,
  );
}
