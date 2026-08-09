import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { requireUser } from '@/lib/auth';
import { getDb, schema } from '@/lib/db';
import { json, errorResponse, readJson } from '@/lib/http';

const schemaBody = z.object({
  notifyEmail: z.boolean().optional(),
  slackWebhookUrl: z.string().url().nullable().optional().or(z.literal('')),
});

export async function PATCH(req: Request) {
  try {
    const user = await requireUser();
    const body = schemaBody.parse(await readJson(req));
    const db = await getDb();
    const updates: Record<string, unknown> = { updatedAt: new Date() };
    if (body.notifyEmail !== undefined) updates.notifyEmail = body.notifyEmail;
    if (body.slackWebhookUrl !== undefined) {
      updates.slackWebhookUrl = body.slackWebhookUrl || null;
    }
    await db.update(schema.users).set(updates).where(eq(schema.users.id, user.id));
    return json({ ok: true });
  } catch (err) {
    return errorResponse(err);
  }
}
