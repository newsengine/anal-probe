/**
 * Sync plan after Checkout return (session_id) or re-pull active Stripe subscription.
 * Fallback when webhooks are delayed / misconfigured.
 */
import { z } from 'zod';
import { requireUser } from '@/lib/auth';
import { activateFromCheckoutSession, syncSubscriptionFromStripe } from '@/lib/stripe';
import { json, errorResponse, readJson } from '@/lib/http';
import { getEntitlements } from '@/lib/entitlements';

const schema = z.object({
  session_id: z.string().optional(),
});

export async function POST(req: Request) {
  try {
    const user = await requireUser();
    const body = schema.parse(await readJson(req).catch(() => ({})));

    if (body.session_id) {
      const result = await activateFromCheckoutSession(user, body.session_id);
      if (!result.ok) return json({ error: result.detail, plan: result.plan, detail: result.detail }, 400);
      const entitlements = await getEntitlements({
        ...user,
        plan: result.plan || user.plan,
      });
      return json({
        ok: true,
        plan: result.plan,
        detail: result.detail,
        entitlements,
      });
    }

    const result = await syncSubscriptionFromStripe(user);
    return json({
      ok: result.ok,
      plan: result.plan,
      detail: result.detail,
    });
  } catch (err) {
    return errorResponse(err);
  }
}
