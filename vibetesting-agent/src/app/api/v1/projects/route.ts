import { z } from 'zod';
import { resolveRequestUser, AuthError } from '@/lib/auth';
import { listProjects, createProject } from '@/lib/projects';
import { json, errorResponse, readJson, clientIp } from '@/lib/http';
import { rateLimit } from '@/lib/rate-limit';

const createSchema = z.object({
  name: z.string().min(1).max(80).optional(),
  url: z.string().min(3).max(500),
  policy: z.enum(['chill', 'ship', 'client', 'launch']).optional(),
});

export async function GET(req: Request) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const projects = await listProjects(user.id);
    return json({ projects });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function POST(req: Request) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const rl = await rateLimit(`proj:${user.id}`, 20, 60_000);
    if (!rl.ok) return json({ error: 'Rate limited' }, 429);
    const body = createSchema.parse(await readJson(req));
    const project = await createProject(user, {
      name: body.name || body.url,
      url: body.url,
      policy: body.policy,
    });
    return json({ project }, 201);
  } catch (err) {
    return errorResponse(err);
  }
}
