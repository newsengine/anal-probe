import Link from 'next/link';
import { getSessionUser } from '@/lib/auth';
import { getLatestRuns } from '@/lib/test-ledger';

const PRIORITY_BADGE: Record<string, { label: string; color: string }> = {
  critical: { label: 'CRITICAL', color: '#ff4d4d' },
  high: { label: 'HIGH', color: '#ff7a45' },
  medium: { label: 'MEDIUM', color: '#ffb020' },
  low: { label: 'LOW', color: '#e6c84f' },
  clean: { label: 'CLEAN', color: '#4dd07a' },
};

export default async function ReportsPage() {
  const user = await getSessionUser();
  if (!user) return null;
  const runs = await getLatestRuns(user.id, 100);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="mono text-2xl font-bold">Reports</h1>
        <span className="text-xs text-[var(--mut)]">every test run + its sub-tests, keyed by VTA number</span>
      </div>
      {runs.length === 0 ? (
        <p className="text-[var(--mut)]">No runs recorded yet — run a scan and it will appear here.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wider text-[var(--mut)]">
              <tr>
                <th className="py-2 pr-3">Priority</th>
                <th className="py-2 pr-3">When</th>
                <th className="py-2 pr-3">Target</th>
                <th className="py-2 pr-3">Run #</th>
                <th className="py-2 pr-3">Passed</th>
                <th className="py-2 pr-3">Failed</th>
                <th className="py-2">By</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => {
                const p = PRIORITY_BADGE[r.priority] || PRIORITY_BADGE.clean;
                return (
                  <tr key={r.id} className="border-t border-[var(--edge)]">
                    <td className="py-2 pr-3">
                      <span className="mono rounded px-2 py-0.5 text-xs font-bold" style={{ color: p.color, border: `1px solid ${p.color}` }}>{p.label}</span>
                    </td>
                    <td className="py-2 pr-3">
                      <Link href={`/dashboard/reports/${r.id}`} className="text-[var(--lime)]">
                        {r.finishedAt?.toISOString?.()?.slice(0, 16) || r.createdAt?.toISOString?.()?.slice(0, 16)}
                      </Link>
                    </td>
                    <td className="mono max-w-[260px] truncate py-2 pr-3">{r.target}</td>
                    <td className="mono py-2 pr-3">#{r.runNumber ?? '—'}</td>
                    <td className="mono py-2 pr-3">{r.passed}</td>
                    <td className="mono py-2 pr-3">🟥 {r.failHigh} · 🟧 {r.failMedium} · 🟨 {r.failLow}</td>
                    <td className="py-2 text-[var(--mut)]">{r.actor}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
