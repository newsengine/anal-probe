import { z } from 'zod';
import { requireUser } from '@/lib/auth';
import { listApiKeys, createApiKey } from '@/lib/api-keys';
import { json, errorResponse, readJson } from '@/lib/http';

export async function GET() {
  try {
    const user = await requireUser();
    const keys = await listApiKeys(user.id);
    return json({ keys });
  } catch (err) {
    return errorResponse(err);
  }
}

const schema = z.object({ name: z.string().min(1).max(60).default('Default') });

export async function POST(req: Request) {
  try {
    const user = await requireUser();
    const body = schema.parse(await readJson(req).catch(() => ({ name: 'Default' })));
    const key = await createApiKey(user.id, body.name);
    return json({
      key: { id: key.id, name: body.name, prefix: key.prefix },
      secret: key.plain, // shown once
      warning: 'Store this API key now. It will not be shown again.',
    }, 201);
  } catch (err) {
    return errorResponse(err);
  }
}
