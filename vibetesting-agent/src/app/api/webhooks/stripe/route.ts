import { handleStripeWebhook } from '@/lib/stripe';
import { json, errorResponse } from '@/lib/http';

export async function POST(req: Request) {
  try {
    const signature = req.headers.get('stripe-signature');
    if (!signature) return json({ error: 'Missing signature' }, 400);
    const rawBody = await req.text();
    await handleStripeWebhook(rawBody, signature);
    return json({ received: true });
  } catch (err) {
    return errorResponse(err);
  }
}
