/**
 * WorkOS AuthKit integration for VibeTesting Agent hosted login.
 * Falls back to GitHub OAuth / dev login when WorkOS is not configured.
 */
import { WorkOS } from '@workos-inc/node';
import { config } from './config';
import { upsertGithubUser, createSession } from './auth';
import { getDb, schema } from './db';
import { eq } from 'drizzle-orm';
import { id } from './ids';
import { audit } from './audit';
import { markEmailVerifiedFromIdp } from './ownership';
import type { User } from './db/schema';

export function getWorkOS(): WorkOS | null {
  if (!config.workos.apiKey || !config.workos.clientId) return null;
  return new WorkOS(config.workos.apiKey, { clientId: config.workos.clientId });
}

export function workosEnabled(): boolean {
  return Boolean(getWorkOS());
}

export function getAuthorizationUrl(state?: string): string {
  const workos = getWorkOS();
  if (!workos) throw new Error('WorkOS is not configured');
  return workos.userManagement.getAuthorizationUrl({
    provider: 'authkit',
    redirectUri: config.workos.redirectUri,
    clientId: config.workos.clientId,
    state,
  });
}

export async function handleWorkOSCallback(code: string): Promise<User> {
  const workos = getWorkOS();
  if (!workos) throw new Error('WorkOS is not configured');

  const { user: woUser } = await workos.userManagement.authenticateWithCode({
    code,
    clientId: config.workos.clientId,
  });

  const email = woUser.email;
  if (!email) throw new Error('WorkOS user has no email');
  // WorkOS AuthKit users who completed magic-link / OTP have emailVerified=true
  const idpEmailVerified = Boolean(
    (woUser as { emailVerified?: boolean }).emailVerified,
  );

  const db = await getDb();
  const now = new Date();
  const existing = await db.select().from(schema.users).where(eq(schema.users.email, email)).limit(1);

  if (existing[0]) {
    await db
      .update(schema.users)
      .set({
        name: [woUser.firstName, woUser.lastName].filter(Boolean).join(' ') || existing[0].name,
        image: woUser.profilePictureUrl || existing[0].image,
        updatedAt: now,
        ...(idpEmailVerified && !existing[0].emailVerifiedAt
          ? { emailVerifiedAt: now, emailVerifyToken: null, emailVerifyExpiresAt: null }
          : {}),
      })
      .where(eq(schema.users.id, existing[0].id));
    const refreshed = await db.select().from(schema.users).where(eq(schema.users.id, existing[0].id)).limit(1);
    await createSession(refreshed[0]!.id);
    await audit('auth.login', { userId: refreshed[0]!.id, detail: { provider: 'workos', emailVerified: idpEmailVerified } });
    return refreshed[0]!;
  }

  // New user via WorkOS — store with synthetic github id slot unused
  const userId = id('usr');
  await db.insert(schema.users).values({
    id: userId,
    email,
    name: [woUser.firstName, woUser.lastName].filter(Boolean).join(' ') || email.split('@')[0],
    image: woUser.profilePictureUrl || null,
    githubId: `workos:${woUser.id}`,
    githubLogin: null,
    plan: 'free',
    planStatus: 'active',
    scansUsedMonth: 0,
    crawlUsedMonth: 0,
    notifyEmail: true,
    emailVerifiedAt: idpEmailVerified ? now : null,
    createdAt: now,
    updatedAt: now,
  });
  await createSession(userId);
  await audit('auth.login', { userId, detail: { provider: 'workos', new: true, emailVerified: idpEmailVerified } });
  if (idpEmailVerified) await markEmailVerifiedFromIdp(userId);
  const created = await db.select().from(schema.users).where(eq(schema.users.id, userId)).limit(1);
  return created[0]!;
}

// silence unused import if tree-shaken
void upsertGithubUser;
