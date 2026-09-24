import Link from 'next/link';
import { getSessionUser } from '@/lib/auth';
import { getRunWithResults } from '@/lib/test-ledger';
import { vtaCode } from '@/lib/vta-numbers';

const PRIORITY_COLOR: Record<string, string> = {
  critical: '#ff4d4d', high: '#ff7a45', medium: '#ffb020', low: '#e6c84f', clean: '#4dd07a',
};
const SEV_RANK: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 };
const SEV_ICON: Record<string, string> = { high: '🟥', medium: '🟧', low: '🟨', info: 'ℹ️' };

export default async function ReportDetailPage({ params }: { params: Promise<{ runId: string }> }) {
  const user = await getSessionUser();
  if (!user) return null;
  const { runId } = await params;
  const data = await getRunWithResults(runId);
  if (!data || data.run.userId !== user.id) {
    return <p className="text-[var(--mut)]">Report not found.</p>;
  }
  const { run, results } = data;
  const color = PRIORITY_COLOR[run.priority] || PRIORITY_COLOR.clean;
  const fails = results.filter((r) => !r.pass).sort((a, b) => (SEV_RANK[a.severity || 'info'] - SEV_RANK[b.severity || 'info']) || ((a.vtaNumber ?? 1e9) - (b.vtaNumber ?? 1e9)));
  const passes = results.filter((r) => r.pass);

  return (
    <div className="space-y-6">
      <Link href="/dashboard/reports" className="text-sm text-[var(--lime)]">&larr; Reports</Link>

      {/* Priority Status — the first-page cover */}
      <div className="rounded-lg border p-5" style={{ borderColor: color }}>
        <div className="mono text-3xl font-bold" style={{ color }}>PRIORITY: {run.priority.toUpperCase()}</div>
        <div className="mono mt-1 break-all text-[var(--mut)]">{run.target}</div>
        <div className="mt-2 text-sm text-[var(--mut)]">
          run #{run.runNumber ?? '—'} · {run.finishedAt?.toISOString?.()?.slice(0, 16)} · by {run.actor}
        </div>
        <div className="mono mt-3 text-sm">
          {run.passed} passed · {run.failed} failed &nbsp; (🟥 {run.failHigh} high · 🟧 {run.failMedium} medium · 🟨 {run.failLow} low)
        </div>
      </div>

      <div>
        <h2 className="mono mb-2 text-lg font-bold">Failing sub-tests ({fails.length})</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wider text-[var(--mut)]">
              <tr><th className="py-2 pr-3">#</th><th className="py-2 pr-3">Sev</th><th className="py-2 pr-3">Category</th><th className="py-2 pr-3">Check</th><th className="py-2">Detail</th></tr>
            </thead>
            <tbody>
              {fails.map((r) => (
                <tr key={r.id} className="border-t border-[var(--edge)]">
                  <td className="mono py-2 pr-3">{r.vtaNumber != null ? vtaCode(r.checkId) : '—'}</td>
                  <td className="py-2 pr-3">{SEV_ICON[r.severity || 'info']}</td>
                  <td className="py-2 pr-3">{r.category}</td>
                  <td className="mono py-2 pr-3">{r.checkId}{r.atlas ? ` [${r.atlas}]` : ''}</td>
                  <td className="max-w-[420px] py-2 text-[var(--mut)]">{r.detail}</td>
                </tr>
              ))}
              {fails.length === 0 && <tr><td colSpan={5} className="py-3 text-[var(--mut)]">No failing checks. ✅</td></tr>}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-[var(--mut)]">{passes.length} checks passed.</p>
      </div>
    </div>
  );
}
