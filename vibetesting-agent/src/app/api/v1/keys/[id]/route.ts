import { requireUser } from '@/lib/auth';
import { revokeApiKey } from '@/lib/api-keys';
import { json, errorResponse } from '@/lib/http';

export async function DELETE(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await requireUser();
    const { id } = await ctx.params;
    await revokeApiKey(user.id, id);
    return json({ ok: true });
  } catch (err) {
    return errorResponse(err);
  }
}
