import { eq, and, isNull } from 'drizzle-orm';
import { getDb, schema } from './db';
import { id, apiKeyPlain } from './ids';
import { hashToken } from './auth';
import { audit } from './audit';

export async function listApiKeys(userId: string) {
  const db = await getDb();
  return db
    .select({
      id: schema.apiKeys.id,
      name: schema.apiKeys.name,
      keyPrefix: schema.apiKeys.keyPrefix,
      lastUsedAt: schema.apiKeys.lastUsedAt,
      createdAt: schema.apiKeys.createdAt,
    })
    .from(schema.apiKeys)
    .where(and(eq(schema.apiKeys.userId, userId), isNull(schema.apiKeys.revokedAt)));
}

export async function createApiKey(userId: string, name: string): Promise<{ id: string; plain: string; prefix: string }> {
  const db = await getDb();
  const { plain, prefix } = apiKeyPlain();
  const keyId = id('key');
  await db.insert(schema.apiKeys).values({
    id: keyId,
    userId,
    name: name || 'Default',
    keyHash: hashToken(plain),
    keyPrefix: prefix,
    createdAt: new Date(),
  });
  await audit('api_key.created', { userId, target: keyId });
  return { id: keyId, plain, prefix };
}

export async function revokeApiKey(userId: string, keyId: string): Promise<void> {
  const db = await getDb();
  await db
    .update(schema.apiKeys)
    .set({ revokedAt: new Date() })
    .where(and(eq(schema.apiKeys.id, keyId), eq(schema.apiKeys.userId, userId)));
  await audit('api_key.revoked', { userId, target: keyId });
}
