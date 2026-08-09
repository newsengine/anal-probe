import { getDb, schema } from './db';
import { id } from './ids';

export async function audit(
  action: string,
  opts: { userId?: string | null; target?: string; detail?: unknown; ip?: string | null } = {},
): Promise<void> {
  const db = await getDb();
  await db.insert(schema.auditLog).values({
    id: id('aud'),
    userId: opts.userId ?? null,
    action,
    target: opts.target ?? null,
    detailJson: opts.detail ? JSON.stringify(opts.detail) : null,
    ip: opts.ip ?? null,
    createdAt: new Date(),
  });
}
