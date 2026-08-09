import { z } from 'zod';
import { requireUser } from '@/lib/auth';
import { setUserPlan } from '@/lib/entitlements';
import { json, errorResponse, readJson } from '@/lib/http';
import { audit } from '@/lib/audit';

const schema = z.object({
  plan: z.enum(['weekly', 'daily', 'commit']).default('weekly'),
});

/** Local/dev only — promotes current user without Stripe. */
export async function POST(req: Request) {
  try {
    if (process.env.NODE_ENV === 'production' && !process.env.ALLOW_DEV_LOGIN) {
      return json({ error: 'Not available' }, 403);
    }
    const user = await requireUser();
    const body = schema.parse(await readJson(req).catch(() => ({ plan: 'weekly' })));
    await setUserPlan(user.id, body.plan, { status: 'active', subscriptionId: `dev_${body.plan}` });
    await audit('billing.dev_upgrade', { userId: user.id, detail: { plan: body.plan } });
    return json({ ok: true, plan: body.plan });
  } catch (err) {
    return errorResponse(err);
  }
}
