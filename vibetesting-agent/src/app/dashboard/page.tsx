import Link from 'next/link';
import { getSessionUser } from '@/lib/auth';
import { getEntitlements } from '@/lib/entitlements';
import { listProjects } from '@/lib/projects';
import { listScansForUser } from '@/lib/scans';
import { config } from '@/lib/config';
import { LitePromptBanner } from '@/components/lite-prompt-banner';

export default async function DashboardPage() {
  const user = await getSessionUser();
  if (!user) return null;
  const entitlements = await getEntitlements(user);
  const projects = await listProjects(user.id);
  const scans = await listScansForUser(user.id, 8);

  return (
    <div className="space-y-8">
      <LitePromptBanner />
      <div>
        <h1 className="mono text-2xl font-bold">Overview</h1>
        <p className="mt-1 text-[var(--mut)]">
          Ship security checks on every update. {entitlements.scansRemaining} scans left this month on{' '}
          <strong className="text-[var(--ink)]">{entitlements.name}</strong>.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-4">
        {[
          ['Plan', entitlements.name],
          ['Projects', `${entitlements.projectCount}/${entitlements.maxProjects}`],
          ['Scans left', String(entitlements.scansRemaining)],
          ['Crawl left', String(entitlements.crawlRemaining)],
        ].map(([k, v]) => (
          <div key={k} className="panel p-4">
            <div className="text-xs uppercase tracking-wider text-[var(--mut)]">{k}</div>
            <div className="mono mt-1 text-xl font-bold">{v}</div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap gap-3">
        <Link href="/dashboard/projects/new" className="btn-primary">
          New project
        </Link>
        <Link href="/dashboard/scans/new" className="btn-ghost">
          Ad-hoc scan
        </Link>
        {user.plan === 'free' && (
          <Link href="/dashboard/billing" className="btn-ghost">
            Upgrade — from $25/mo
          </Link>
        )}
      </div>

      <section>
        <h2 className="mono text-lg font-bold">Projects</h2>
        {projects.length === 0 ? (
          <p className="mt-2 text-sm text-[var(--mut)]">No projects yet. Add a deploy URL to enable Ship Check.</p>
        ) : (
          <div className="mt-3 grid gap-3">
            {projects.map((p) => (
              <Link key={p.id} href={`/dashboard/projects/${p.id}`} className="panel block p-4 hover:border-[var(--lime)]">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="font-semibold">{p.name}</div>
                    <div className="mono text-xs text-[var(--mut)]">{p.url}</div>
                  </div>
                  <div className="text-right">
                    <div className="mono text-2xl font-extrabold text-[var(--lime)]">{p.lastGrade || '—'}</div>
                    <div className="text-xs text-[var(--mut)]">
                      {p.verified ? 'verified' : 'unverified'} · {p.policy}
                    </div>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </section>

      <section>
        <h2 className="mono text-lg font-bold">Recent scans</h2>
        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wider text-[var(--mut)]">
              <tr>
                <th className="py-2 pr-3">When</th>
                <th className="py-2 pr-3">URL</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Score</th>
                <th className="py-2">Trigger</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="border-t border-[var(--edge)]">
                  <td className="py-2 pr-3 text-[var(--mut)]">
                    <Link href={`/dashboard/scans/${s.id}`} className="hover:text-[var(--lime)]">
                      {s.createdAt?.toISOString?.()?.slice(0, 16) || '—'}
                    </Link>
                  </td>
                  <td className="mono py-2 pr-3 max-w-[240px] truncate">{s.url}</td>
                  <td className="py-2 pr-3">{s.status}</td>
                  <td className="mono py-2 pr-3">
                    {s.grade || '—'} {s.score != null ? `(${s.score})` : ''}
                  </td>
                  <td className="py-2 text-[var(--mut)]">{s.trigger}</td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-4 text-[var(--mut)]">
                    No scans yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel p-5 text-sm text-[var(--mut)]">
        <h3 className="mono font-bold text-[var(--ink)]">Quick links</h3>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>
            MCP setup: <Link className="text-[var(--lime)]" href="/dashboard/mcp">{config.appUrl}/dashboard/mcp</Link>
          </li>
          <li>
            API: <code className="text-[var(--ink)]">Authorization: Bearer sk_live_…</code> →{' '}
            <code className="text-[var(--ink)]">POST /api/v1/scans</code>
          </li>
          <li>OSS CLI remains free forever for local/CI.</li>
        </ul>
      </section>
    </div>
  );
}
