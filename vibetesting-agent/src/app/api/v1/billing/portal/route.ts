import { requireUser } from '@/lib/auth';
import { createBillingPortalSession, stripeConfigured } from '@/lib/stripe';
import { json, errorResponse } from '@/lib/http';

export async function POST() {
  try {
    if (!stripeConfigured()) {
      return json({ error: 'Stripe is not configured on this deployment.' }, 503);
    }
    const user = await requireUser();
    const url = await createBillingPortalSession(user);
    return json({ url });
  } catch (err) {
    return errorResponse(err);
  }
}
