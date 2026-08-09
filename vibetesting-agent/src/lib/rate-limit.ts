import { eq } from 'drizzle-orm';
import { getDb, schema } from './db';

/** Simple sliding fixed-window rate limit. Returns true if allowed. */
export async function rateLimit(
  key: string,
  limit: number,
  windowMs: number,
): Promise<{ ok: boolean; remaining: number }> {
  const db = await getDb();
  const now = Date.now();
  const rows = await db.select().from(schema.rateLimits).where(eq(schema.rateLimits.key, key)).limit(1);
  const row = rows[0];

  if (!row || now - row.windowStart.getTime() > windowMs) {
    await db
      .insert(schema.rateLimits)
      .values({ key, count: 1, windowStart: new Date(now) })
      .onConflictDoUpdate({
        target: schema.rateLimits.key,
        set: { count: 1, windowStart: new Date(now) },
      });
    return { ok: true, remaining: limit - 1 };
  }

  if (row.count >= limit) {
    return { ok: false, remaining: 0 };
  }

  await db
    .update(schema.rateLimits)
    .set({ count: row.count + 1 })
    .where(eq(schema.rateLimits.key, key));
  return { ok: true, remaining: limit - row.count - 1 };
}
