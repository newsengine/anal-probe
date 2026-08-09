import { cookies } from 'next/headers';
import { eq, and, gt } from 'drizzle-orm';
import { createHash, randomBytes } from 'node:crypto';
import { getDb, schema } from './db';
import { id } from './ids';
import type { User } from './db/schema';

const SESSION_COOKIE = 'vta_session';
const SESSION_DAYS = 30;

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export async function createSession(userId: string): Promise<string> {
  const db = await getDb();
  const sessionId = randomBytes(32).toString('base64url');
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await db.insert(schema.sessions).values({
    id: sessionId,
    userId,
    expiresAt: expires,
    createdAt: now,
  });
  const jar = await cookies();
  jar.set(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    expires,
  });
  return sessionId;
}

export async function destroySession(): Promise<void> {
  const jar = await cookies();
  const sid = jar.get(SESSION_COOKIE)?.value;
  if (sid) {
    const db = await getDb();
    await db.delete(schema.sessions).where(eq(schema.sessions.id, sid));
    jar.delete(SESSION_COOKIE);
  }
}

export async function getSessionUser(): Promise<User | null> {
  const jar = await cookies();
  const sid = jar.get(SESSION_COOKIE)?.value;
  if (!sid) return null;
  const db = await getDb();
  const now = new Date();
  const rows = await db
    .select({ user: schema.users })
    .from(schema.sessions)
    .innerJoin(schema.users, eq(schema.sessions.userId, schema.users.id))
    .where(and(eq(schema.sessions.id, sid), gt(schema.sessions.expiresAt, now)))
    .limit(1);
  return rows[0]?.user ?? null;
}

export async function requireUser(): Promise<User> {
  const user = await getSessionUser();
  if (!user) throw new AuthError('Unauthorized');
  return user;
}

export class AuthError extends Error {
  status = 401;
  constructor(message = 'Unauthorized') {
    super(message);
    this.name = 'AuthError';
  }
}

export class ForbiddenError extends Error {
  status = 403;
  constructor(message = 'Forbidden') {
    super(message);
    this.name = 'ForbiddenError';
  }
}

export class QuotaError extends Error {
  status = 402;
  constructor(message = 'Quota exceeded') {
    super(message);
    this.name = 'QuotaError';
  }
}

/** Upsert user from GitHub OAuth profile. */
export async function upsertGithubUser(profile: {
  id: number | string;
  login: string;
  email?: string | null;
  name?: string | null;
  avatar_url?: string | null;
}): Promise<User> {
  const db = await getDb();
  const githubId = String(profile.id);
  const email = profile.email || `${profile.login}@users.noreply.github.com`;
  const now = new Date();

  const existing = await db.select().from(schema.users).where(eq(schema.users.githubId, githubId)).limit(1);
  if (existing[0]) {
    await db
      .update(schema.users)
      .set({
        email,
        name: profile.name || profile.login,
        image: profile.avatar_url || null,
        githubLogin: profile.login,
        updatedAt: now,
      })
      .where(eq(schema.users.id, existing[0].id));
    const refreshed = await db.select().from(schema.users).where(eq(schema.users.id, existing[0].id)).limit(1);
    return refreshed[0]!;
  }

  const userId = id('usr');
  await db.insert(schema.users).values({
    id: userId,
    email,
    name: profile.name || profile.login,
    image: profile.avatar_url || null,
    githubId,
    githubLogin: profile.login,
    plan: 'free',
    planStatus: 'active',
    scansUsedMonth: 0,
    crawlUsedMonth: 0,
    usageMonth: monthKey(now),
    notifyEmail: true,
    createdAt: now,
    updatedAt: now,
  });
  const created = await db.select().from(schema.users).where(eq(schema.users.id, userId)).limit(1);
  return created[0]!;
}

export function monthKey(d = new Date()): string {
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

/** Authenticate API key (Authorization: Bearer sk_live_…). */
export async function authApiKey(authHeader: string | null): Promise<User | null> {
  if (!authHeader?.startsWith('Bearer ')) return null;
  const plain = authHeader.slice(7).trim();
  if (!plain.startsWith('sk_live_') && !plain.startsWith('sk_test_')) return null;
  const db = await getDb();
  const keyHash = hashToken(plain);
  const keys = await db
    .select()
    .from(schema.apiKeys)
    .where(eq(schema.apiKeys.keyHash, keyHash))
    .limit(1);
  const key = keys[0];
  if (!key || key.revokedAt) return null;
  await db.update(schema.apiKeys).set({ lastUsedAt: new Date() }).where(eq(schema.apiKeys.id, key.id));
  const users = await db.select().from(schema.users).where(eq(schema.users.id, key.userId)).limit(1);
  return users[0] ?? null;
}

export async function resolveRequestUser(req: Request): Promise<User | null> {
  const fromKey = await authApiKey(req.headers.get('authorization'));
  if (fromKey) return fromKey;
  return getSessionUser();
}
