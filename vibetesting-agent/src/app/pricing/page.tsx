import Link from 'next/link';
import { PLANS } from '@/lib/plans';

export default function PricingPage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-16">
      <Link href="/" className="mono text-[var(--lime)]">
        ← VibeTesting Agent
      </Link>
      <h1 className="mono mt-6 text-3xl font-bold">Pricing</h1>
      <p className="mt-2 text-[var(--mut)]">
        OSS CLI free forever. Hosted continuous scanning for apps you prove you own.
      </p>
      <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Object.values(PLANS).map((p) => (
          <div key={p.id} className={`panel p-6 ${p.id === 'commit' ? 'ring-1 ring-[var(--lime)]' : ''}`}>
            <div className="mono text-[var(--mut)]">{p.name}</div>
            <div className="mt-2 text-4xl font-extrabold">${p.priceMonthlyUsd}</div>
            <div className="text-sm text-[var(--mut)]">per month</div>
            <p className="mt-3 text-sm text-[var(--mut)]">{p.tagline}</p>
            <Link href="/login" className="btn-primary mt-6 w-full">
              Get started
            </Link>
          </div>
        ))}
      </div>
    </div>
  );
}
