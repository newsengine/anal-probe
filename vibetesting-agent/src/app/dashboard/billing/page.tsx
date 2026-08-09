import { getSessionUser } from '@/lib/auth';
import { getEntitlements } from '@/lib/entitlements';
import { publicConfig } from '@/lib/config';
import { PLANS } from '@/lib/plans';
import { stripeConfigured, activateFromCheckoutSession, syncSubscriptionFromStripe } from '@/lib/stripe';
import { BillingPlanCards } from '@/components/forms';

export default async function BillingPage({
  searchParams,
}: {
  searchParams: Promise<{ success?: string; canceled?: string; session_id?: string }>;
}) {
  let user = await getSessionUser();
  if (!user) return null;
  const sp = await searchParams;

  // After Stripe Checkout redirect: activate plan immediately (don't wait on webhook)
  let syncMessage = '';
  if (sp.session_id) {
    const result = await activateFromCheckoutSession(user, sp.session_id);
    if (result.ok) {
      syncMessage = `Payment received — you're on the ${result.plan} plan.`;
      user = (await getSessionUser()) ?? user;
    } else {
      const s = await syncSubscriptionFromStripe(user);
      if (s.ok && s.plan !== 'free') {
        syncMessage = `Synced subscription: ${s.plan}.`;
        user = (await getSessionUser()) ?? user;
      } else {
        syncMessage = `Checkout returned but plan not active yet: ${result.detail}. Use “Refresh plan from Stripe”.`;
      }
    }
  } else if (sp.success) {
    const s = await syncSubscriptionFromStripe(user);
    if (s.ok && s.plan !== 'free') {
      syncMessage = `Synced subscription: ${s.plan}.`;
      user = (await getSessionUser()) ?? user;
    } else {
      syncMessage =
        'Checkout completed — if your plan still shows Lite, click “Refresh plan from Stripe” (webhook may be delayed).';
    }
  }

  const entitlements = await getEntitlements(user);
  const pub = publicConfig();
  const enabled = pub.stripeEnabled || stripeConfigured();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="mono text-2xl font-bold">Billing</h1>
        <p className="mt-1 text-sm text-[var(--mut)]">
          Pick the cadence that matches how hard you&apos;re shipping.
        </p>
      </div>

      {syncMessage && (
        <p className="rounded-lg border border-[var(--lime)]/40 bg-[var(--lime)]/10 px-3 py-2 text-sm text-[var(--lime)]">
          {syncMessage}
        </p>
      )}
      {sp.canceled && <p className="text-sm text-[var(--mut)]">Checkout canceled — no charge.</p>}

      <div className="panel p-5">
        <div className="text-sm text-[var(--mut)]">Current plan</div>
        <div className="mono text-3xl font-extrabold text-[var(--lime)]">{entitlements.name}</div>
        <div className="mt-2 text-sm text-[var(--mut)]">
          {entitlements.tagline} · {entitlements.scansRemaining} scans left · status {user!.planStatus}
        </div>
        {user!.stripeCustomerId && (
          <div className="mono mt-2 text-xs text-[var(--mut)]">Stripe customer: {user!.stripeCustomerId}</div>
        )}
      </div>

      <BillingPlanCards stripeEnabled={enabled} currentPlan={entitlements.id} />
    </div>
  );
}
