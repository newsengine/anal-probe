import Stripe from 'stripe';
import { eq } from 'drizzle-orm';
import { config } from './config';
import { getDb, schema } from './db';
import { setUserPlan } from './entitlements';
import { audit } from './audit';
import type { User } from './db/schema';
import type { PlanId } from './plans';

let _stripe: Stripe | null | undefined;

/**
 * Stripe client for Cloudflare Workers / Node.
 * Must use the fetch HTTP client — Node's default `http` module hangs under OpenNext Workers.
 */
export function getStripe(): Stripe | null {
  if (_stripe !== undefined) return _stripe;
  if (!config.stripe.secretKey) {
    _stripe = null;
    return null;
  }
  _stripe = new Stripe(config.stripe.secretKey, {
    httpClient: Stripe.createFetchHttpClient(),
    typescript: true,
  });
  return _stripe;
}

export function stripeConfigured(): boolean {
  return Boolean(
    config.stripe.secretKey &&
      (config.stripe.priceWeekly || config.stripe.priceDaily || config.stripe.priceCommit),
  );
}

function priceForPlan(plan: PlanId): string | undefined {
  if (plan === 'weekly') return config.stripe.priceWeekly || undefined;
  if (plan === 'daily') return config.stripe.priceDaily || undefined;
  if (plan === 'commit') return config.stripe.priceCommit || undefined;
  return undefined;
}

function normalizePlan(plan: string | null | undefined): PlanId {
  if (plan === 'vibe' || plan === 'weekly') return 'weekly';
  if (plan === 'studio' || plan === 'daily') return 'daily';
  if (plan === 'commit') return 'commit';
  return 'weekly';
}

function planFromPriceId(priceId: string | null | undefined): PlanId | null {
  if (!priceId) return null;
  if (priceId === config.stripe.priceWeekly) return 'weekly';
  if (priceId === config.stripe.priceDaily) return 'daily';
  if (priceId === config.stripe.priceCommit) return 'commit';
  return null;
}

export async function ensureStripeCustomer(user: User): Promise<string> {
  const stripe = getStripe();
  if (!stripe) throw new Error('Stripe is not configured');
  const db = await getDb();

  // Reuse existing customer only if it still exists on the *current* Stripe account
  // (stale IDs from a previous account / test mode cause "No such customer").
  if (user.stripeCustomerId) {
    try {
      const existing = await stripe.customers.retrieve(user.stripeCustomerId);
      if (!('deleted' in existing && existing.deleted)) {
        return existing.id;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const missing =
        msg.includes('No such customer') ||
        (typeof err === 'object' &&
          err !== null &&
          'code' in err &&
          (err as { code?: string }).code === 'resource_missing');
      if (!missing) throw err;
      // Clear stale id and recreate below
      await db
        .update(schema.users)
        .set({ stripeCustomerId: null, updatedAt: new Date() })
        .where(eq(schema.users.id, user.id));
    }
  }

  // Prefer matching an existing customer on this account by email + our metadata
  if (user.email) {
    const listed = await stripe.customers.list({ email: user.email, limit: 5 });
    const match =
      listed.data.find((c) => c.metadata?.vta_user_id === user.id) || listed.data[0];
    if (match) {
      await db
        .update(schema.users)
        .set({ stripeCustomerId: match.id, updatedAt: new Date() })
        .where(eq(schema.users.id, user.id));
      return match.id;
    }
  }

  const customer = await stripe.customers.create({
    email: user.email,
    name: user.name || undefined,
    metadata: { vta_user_id: user.id },
  });
  await db
    .update(schema.users)
    .set({ stripeCustomerId: customer.id, updatedAt: new Date() })
    .where(eq(schema.users.id, user.id));
  return customer.id;
}

export async function createCheckoutSession(
  user: User,
  plan: 'weekly' | 'daily' | 'commit' | 'vibe' | 'studio',
): Promise<string> {
  const stripe = getStripe();
  if (!stripe) throw new Error('Stripe is not configured');

  const normalized = normalizePlan(plan);
  const price = priceForPlan(normalized);
  if (!price) {
    throw new Error(
      `Missing Stripe price for plan "${normalized}". Set STRIPE_PRICE_WEEKLY / _DAILY / _COMMIT on the Worker.`,
    );
  }

  const customerId = await ensureStripeCustomer(user);

  // If they already have an active sub, send them to the portal instead of double-subscribing
  const existing = await stripe.subscriptions.list({
    customer: customerId,
    status: 'active',
    limit: 1,
  });
  if (existing.data.length > 0) {
    const portal = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${config.appUrl}/dashboard/billing`,
    });
    return portal.url;
  }

  // Private founder discount: auto-apply coupon server-side (no public promo box).
  // Stripe forbids combining `discounts` with `allow_promotion_codes`.
  const founderDiscount = founderCommitDiscount(user.email, normalized);

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    customer: customerId,
    client_reference_id: user.id,
    line_items: [{ price, quantity: 1 }],
    success_url: `${config.appUrl}/dashboard/billing?success=1&session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${config.appUrl}/dashboard/billing?canceled=1`,
    metadata: {
      vta_user_id: user.id,
      plan: normalized,
      ...(founderDiscount ? { founder_discount: '1' } : {}),
    },
    subscription_data: {
      metadata: { vta_user_id: user.id, plan: normalized },
    },
    // Always brand as VibeTesting Agent — never inherit a misnamed Stripe account label
    // (e.g. leftover demo account display names).
    branding_settings: {
      display_name: 'VibeTesting Agent',
      button_color: '#a3e635',
      background_color: '#0a0a0a',
      border_style: 'rounded',
    },
    custom_text: {
      submit: {
        message: 'VibeTesting Agent — security scans for vibe-coded apps',
      },
    },
    ...(founderDiscount
      ? { discounts: founderDiscount }
      : config.stripe.allowPromotionCodes
        ? { allow_promotion_codes: true }
        : {}),
    billing_address_collection: 'auto',
    // Explicit so Checkout always presents a card form
    payment_method_types: ['card'],
  });
  if (!session.url) throw new Error('Stripe Checkout did not return a URL');
  return session.url;
}

/** Server-side only: founder emails get the private commit coupon (e.g. $1 first month). */
function founderCommitDiscount(
  email: string | null | undefined,
  plan: PlanId,
): { coupon: string }[] | null {
  if (plan !== 'commit') return null;
  const coupon = config.stripe.founderCommitCouponId?.trim();
  if (!coupon) return null;
  const allow = config.stripe.founderBillingEmails
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  if (!allow.length) return null;
  const who = (email || '').trim().toLowerCase();
  if (!who || !allow.includes(who)) return null;
  return [{ coupon }];
}

export async function createBillingPortalSession(user: User): Promise<string> {
  const stripe = getStripe();
  if (!stripe) throw new Error('Stripe is not configured');
  const customerId = await ensureStripeCustomer(user);
  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: `${config.appUrl}/dashboard/billing`,
  });
  return session.url;
}

/**
 * Activate plan from a completed Checkout Session (success-page fallback when webhooks lag).
 */
export async function activateFromCheckoutSession(
  user: User,
  sessionId: string,
): Promise<{ ok: boolean; plan?: PlanId; detail: string }> {
  const stripe = getStripe();
  if (!stripe) return { ok: false, detail: 'Stripe not configured' };
  if (!sessionId.startsWith('cs_')) return { ok: false, detail: 'Invalid session id' };

  const session = await stripe.checkout.sessions.retrieve(sessionId, {
    expand: ['subscription', 'line_items.data.price'],
  });

  const metaUser = session.metadata?.vta_user_id || session.client_reference_id;
  if (metaUser && metaUser !== user.id) {
    return { ok: false, detail: 'Checkout session belongs to a different account' };
  }
  if (session.customer && user.stripeCustomerId && session.customer !== user.stripeCustomerId) {
    // Still allow if email matches and metadata user matches
    if (metaUser !== user.id) {
      return { ok: false, detail: 'Checkout customer mismatch' };
    }
  }

  if (session.status !== 'complete' && session.payment_status !== 'paid') {
    return {
      ok: false,
      detail: `Checkout not complete yet (status=${session.status}, payment=${session.payment_status})`,
    };
  }

  let plan = normalizePlan(session.metadata?.plan);
  // Prefer price id mapping if metadata missing
  const linePrice =
    typeof session.line_items?.data?.[0]?.price === 'object'
      ? session.line_items.data[0].price?.id
      : undefined;
  const fromPrice = planFromPriceId(linePrice);
  if (fromPrice) plan = fromPrice;

  const subId =
    typeof session.subscription === 'string'
      ? session.subscription
      : session.subscription?.id || null;

  // Persist customer id if we didn't have it
  if (session.customer && !user.stripeCustomerId) {
    const db = await getDb();
    await db
      .update(schema.users)
      .set({
        stripeCustomerId: String(session.customer),
        updatedAt: new Date(),
      })
      .where(eq(schema.users.id, user.id));
  }

  await setUserPlan(user.id, plan, {
    subscriptionId: subId,
    status: 'active',
  });
  await audit('billing.checkout_synced', {
    userId: user.id,
    detail: { plan, sessionId, subId },
  });

  return { ok: true, plan, detail: `Plan set to ${plan}` };
}

/**
 * Re-read Stripe subscriptions for this customer and align local plan.
 */
export async function syncSubscriptionFromStripe(
  user: User,
): Promise<{ ok: boolean; plan: PlanId; detail: string }> {
  const stripe = getStripe();
  if (!stripe) return { ok: false, plan: 'free', detail: 'Stripe not configured' };

  const customerId = user.stripeCustomerId || (await ensureStripeCustomer(user));
  const subs = await stripe.subscriptions.list({
    customer: customerId,
    status: 'all',
    limit: 10,
    expand: ['data.items.data.price'],
  });

  const active = subs.data.find((s) => s.status === 'active' || s.status === 'trialing');
  if (!active) {
    if (user.plan !== 'free') {
      await setUserPlan(user.id, 'free', { subscriptionId: null, status: 'canceled' });
    }
    return { ok: true, plan: 'free', detail: 'No active subscription' };
  }

  const priceId = active.items.data[0]?.price?.id;
  const plan = planFromPriceId(priceId) || normalizePlan(active.metadata?.plan);
  await setUserPlan(user.id, plan, { subscriptionId: active.id, status: active.status });
  await audit('billing.sync', { userId: user.id, detail: { plan, sub: active.id } });
  return { ok: true, plan, detail: `Synced active plan ${plan}` };
}

export async function handleStripeWebhook(rawBody: string, signature: string): Promise<void> {
  const stripe = getStripe();
  if (!stripe || !config.stripe.webhookSecret) throw new Error('Stripe webhook not configured');

  // Workers: use SubtleCrypto-backed async verification (Node crypto often unavailable)
  const event = await stripe.webhooks.constructEventAsync(
    rawBody,
    signature,
    config.stripe.webhookSecret,
    undefined,
    Stripe.createSubtleCryptoProvider(),
  );
  const db = await getDb();

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session;
      const userId = session.metadata?.vta_user_id || session.client_reference_id || undefined;
      let plan = normalizePlan(session.metadata?.plan);

      if (userId) {
        // Map price if present
        try {
          const full = await stripe.checkout.sessions.retrieve(session.id, {
            expand: ['line_items.data.price'],
          });
          const priceId = full.line_items?.data?.[0]?.price;
          const id = typeof priceId === 'object' && priceId ? priceId.id : undefined;
          const mapped = planFromPriceId(id);
          if (mapped) plan = mapped;
        } catch {
          /* keep metadata plan */
        }

        if (session.customer) {
          await db
            .update(schema.users)
            .set({
              stripeCustomerId: String(session.customer),
              updatedAt: new Date(),
            })
            .where(eq(schema.users.id, userId));
        }

        await setUserPlan(userId, plan, {
          subscriptionId:
            typeof session.subscription === 'string'
              ? session.subscription
              : session.subscription?.id,
          status: 'active',
        });
        await audit('billing.checkout_completed', { userId, detail: { plan, session: session.id } });
      }
      break;
    }
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const sub = event.data.object as Stripe.Subscription;
      const userId = sub.metadata?.vta_user_id;
      const customers = await db
        .select()
        .from(schema.users)
        .where(eq(schema.users.stripeCustomerId, String(sub.customer)))
        .limit(1);
      const uid = userId || customers[0]?.id;
      if (!uid) break;

      if (event.type === 'customer.subscription.deleted' || sub.status === 'canceled') {
        await setUserPlan(uid, 'free', { subscriptionId: null, status: 'canceled' });
        await audit('billing.subscription_canceled', { userId: uid });
      } else {
        const priceId = sub.items?.data?.[0]?.price?.id;
        const plan = planFromPriceId(priceId) || normalizePlan(sub.metadata?.plan);
        await setUserPlan(uid, plan, { subscriptionId: sub.id, status: sub.status });
        await audit('billing.subscription_updated', {
          userId: uid,
          detail: { plan, status: sub.status },
        });
      }
      break;
    }
    case 'invoice.paid': {
      const invoice = event.data.object as Stripe.Invoice;
      const customers = await db
        .select()
        .from(schema.users)
        .where(eq(schema.users.stripeCustomerId, String(invoice.customer)))
        .limit(1);
      if (customers[0]) {
        await audit('billing.invoice_paid', {
          userId: customers[0].id,
          detail: { amount: invoice.amount_paid },
        });
        // Ensure plan stays active after invoice
        await syncSubscriptionFromStripe(customers[0]);
      }
      break;
    }
    default:
      break;
  }
}
