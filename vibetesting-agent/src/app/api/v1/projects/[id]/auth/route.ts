/**
 * Project authenticated-scan access (opt-in test session).
 * GET status · PUT save · POST verify · DELETE clear/opt-out
 */
import { z } from 'zod';
import { resolveRequestUser, AuthError } from '@/lib/auth';
import { getProject } from '@/lib/projects';
import {
  authPublicStatus,
  saveProjectAuth,
  clearProjectAuth,
  verifyProjectAuth,
} from '@/lib/project-auth';
import { json, errorResponse, readJson } from '@/lib/http';

const putSchema = z.object({
  enabled: z.boolean(),
  mode: z.enum(['cookie', 'bearer', 'password']),
  email: z.string().email().optional().nullable().or(z.literal('')),
  /** Session cookie, bearer token, or password (or JSON for password mode) */
  secret: z.string().min(1).max(8000).optional().nullable(),
  loginUrl: z.string().max(500).optional().nullable().or(z.literal('')),
  keepExistingSecret: z.boolean().optional(),
});

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const project = await getProject(user.id, id);
    if (!project) return json({ error: 'Project not found' }, 404);
    return json({ auth: authPublicStatus(project) });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function PUT(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const body = putSchema.parse(await readJson(req));
    const project = await saveProjectAuth(user, id, {
      enabled: body.enabled,
      mode: body.mode,
      email: body.email || null,
      secret: body.secret || null,
      loginUrl: body.loginUrl || null,
      keepExistingSecret: body.keepExistingSecret ?? !body.secret,
    });
    return json({ auth: authPublicStatus(project) });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const result = await verifyProjectAuth(user, id);
    const project = await getProject(user.id, id);
    return json({
      ...result,
      auth: project ? authPublicStatus(project) : null,
    });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const project = await clearProjectAuth(user, id);
    return json({
      ok: true,
      auth: authPublicStatus(project),
      detail: 'Authenticated testing disabled. Test credentials deleted.',
    });
  } catch (err) {
    return errorResponse(err);
  }
}
