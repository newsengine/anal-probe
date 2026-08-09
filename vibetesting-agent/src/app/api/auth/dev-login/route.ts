import { NextResponse } from 'next/server';
import { config } from '@/lib/config';
import { createSession, upsertGithubUser } from '@/lib/auth';
import { audit } from '@/lib/audit';

/** Local-only login when GitHub OAuth is not configured. Disabled in production. */
export async function GET() {
  if (process.env.NODE_ENV === 'production' && !process.env.ALLOW_DEV_LOGIN) {
    return NextResponse.json({ error: 'Dev login disabled' }, { status: 403 });
  }
  const user = await upsertGithubUser({
    id: 'dev-1',
    login: 'vibe-coder',
    email: 'dev@vibetestingagent.local',
    name: 'Vibe Coder',
    avatar_url: null,
  });
  await createSession(user.id);
  await audit('auth.login', { userId: user.id, detail: { provider: 'dev' } });
  return NextResponse.redirect(new URL('/dashboard', config.appUrl));
}
