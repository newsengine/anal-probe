import Link from 'next/link';
import { getSessionUser } from '@/lib/auth';
import { listScansForUser } from '@/lib/scans';

export default async function ScansPage() {
  const user = await getSessionUser();
  if (!user) return null;
  const scans = await listScansForUser(user.id, 100);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="mono text-2xl font-bold">Scans</h1>
        <Link href="/dashboard/scans/new" className="btn-primary">
          New scan
        </Link>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase tracking-wider text-[var(--mut)]">
            <tr>
              <th className="py-2 pr-3">When</th>
              <th className="py-2 pr-3">URL</th>
              <th className="py-2 pr-3">Mode</th>
              <th className="py-2 pr-3">Status</th>
              <th className="py-2 pr-3">Score</th>
              <th className="py-2">Trigger</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id} className="border-t border-[var(--edge)]">
                <td className="py-2 pr-3">
                  <Link href={`/dashboard/scans/${s.id}`} className="text-[var(--lime)]">
                    {s.createdAt?.toISOString?.()?.slice(0, 16)}
                  </Link>
                </td>
                <td className="mono max-w-[260px] truncate py-2 pr-3">{s.url}</td>
                <td className="py-2 pr-3">{s.mode}</td>
                <td className="py-2 pr-3">{s.status}</td>
                <td className="mono py-2 pr-3">
                  {s.grade || '—'} {s.score != null ? s.score : ''}
                </td>
                <td className="py-2 text-[var(--mut)]">{s.trigger}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
