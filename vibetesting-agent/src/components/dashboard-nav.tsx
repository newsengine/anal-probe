import Link from 'next/link';
import type { User } from '@/lib/db/schema';

export function DashboardNav({ user }: { user: User }) {
  const links = [
    ['/dashboard', 'Overview'],
    ['/dashboard/projects', 'Projects'],
    ['/dashboard/scans', 'Scans'],
    ['/dashboard/reports', 'Reports'],
    ['/dashboard/keys', 'API keys'],
    ['/dashboard/billing', 'Billing'],
    ['/dashboard/settings', 'Settings'],
    ['/dashboard/mcp', 'Claude / Codex'],
  ] as const;

  return (
    <header className="border-b border-[var(--edge)] bg-[var(--bg)]/90 backdrop-blur">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-6 py-3">
        <div className="flex items-center gap-6">
          <Link href="/dashboard" className="mono font-extrabold text-[var(--lime)]">
            VibeTesting
          </Link>
          <nav className="flex flex-wrap gap-3 text-sm">
            {links.map(([href, label]) => (
              <Link key={href} href={href} className="text-[var(--mut)] hover:text-[var(--ink)]">
                {label}
              </Link>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-3 text-sm">
          <span className="rounded-full border border-[var(--edge)] px-2.5 py-0.5 mono text-xs uppercase text-[var(--lime)]">
            {user.plan}
          </span>
          <span className="text-[var(--mut)]">{user.name || user.email}</span>
          <form action="/api/auth/logout" method="POST">
            <button type="submit" className="text-[var(--mut)] hover:text-[var(--hi)]">
              Log out
            </button>
          </form>
        </div>
      </div>
    </header>
  );
}
