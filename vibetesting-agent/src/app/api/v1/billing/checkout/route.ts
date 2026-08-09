import { z } from 'zod';
import { requireUser } from '@/lib/auth';
import { createCheckoutSession, stripeConfigured } from '@/lib/stripe';
import { json, errorResponse, readJson } from '@/lib/http';

const schema = z.object({
  plan: z.enum(['weekly', 'daily', 'commit', 'vibe', 'studio']).default('weekly'),
});

export async function POST(req: Request) {
  try {
    if (!stripeConfigured()) {
      return json(
        {
          error:
            'Stripe is not configured on this deployment. Set STRIPE_SECRET_KEY and STRIPE_PRICE_WEEKLY / _DAILY / _COMMIT.',
        },
        503,
      );
    }
    const user = await requireUser();
    const body = schema.parse(await readJson(req).catch(() => ({ plan: 'weekly' })));
    const url = await createCheckoutSession(user, body.plan);
    return json({ url });
  } catch (err) {
    return errorResponse(err);
  }
}
