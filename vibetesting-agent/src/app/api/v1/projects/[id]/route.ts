import { z } from 'zod';
import { resolveRequestUser, AuthError } from '@/lib/auth';
import { getProject, updateProject, deleteProject } from '@/lib/projects';
import { json, errorResponse, readJson } from '@/lib/http';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const project = await getProject(user.id, id);
    if (!project) return json({ error: 'Not found' }, 404);
    return json({ project });
  } catch (err) {
    return errorResponse(err);
  }
}

const patchSchema = z.object({
  name: z.string().min(1).max(80).optional(),
  url: z.string().min(3).max(500).optional(),
  policy: z.enum(['chill', 'ship', 'client', 'launch']).optional(),
  shipCheckEnabled: z.boolean().optional(),
  githubRepo: z.string().nullable().optional(),
  badgePublic: z.boolean().optional(),
});

export async function PATCH(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const body = patchSchema.parse(await readJson(req));
    const project = await updateProject(user.id, id, body);
    return json({ project });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    await deleteProject(user.id, id);
    return json({ ok: true });
  } catch (err) {
    return errorResponse(err);
  }
}
