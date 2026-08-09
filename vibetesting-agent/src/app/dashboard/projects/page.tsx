import Link from 'next/link';
import { getSessionUser } from '@/lib/auth';
import { listProjects } from '@/lib/projects';

export default async function ProjectsPage({
  searchParams,
}: {
  searchParams: Promise<{ email_verified?: string }>;
}) {
  const user = await getSessionUser();
  if (!user) return null;
  const sp = await searchParams;
  const projects = await listProjects(user.id);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="mono text-2xl font-bold">Projects</h1>
        <Link href="/dashboard/projects/new" className="btn-primary">
          New project
        </Link>
      </div>
      {sp.email_verified === '1' && (
        <div className="rounded-lg border border-[var(--lime)]/40 bg-[var(--lime)]/10 px-4 py-3 text-sm">
          Inbox verified for <code className="text-[var(--ink)]">{user.email}</code>. Open a project and
          choose <strong>Verify with domain email</strong> if the address matches the app domain — or use DNS
          TXT.
        </div>
      )}
      <div className="grid gap-3">
        {projects.map((p) => (
          <Link key={p.id} href={`/dashboard/projects/${p.id}`} className="panel p-4 hover:border-[var(--lime)]">
            <div className="flex justify-between gap-4">
              <div>
                <div className="font-semibold">{p.name}</div>
                <div className="mono text-xs text-[var(--mut)]">{p.url}</div>
                <div className="mt-1 text-xs text-[var(--mut)]">
                  {p.verified ? (
                    <span className="text-[var(--lime)]">
                      Ownership verified{p.verifyMethod ? ` · ${p.verifyMethod}` : ''}
                    </span>
                  ) : (
                    <span className="text-[var(--md)]">Ownership pending (domain email or DNS)</span>
                  )}
                </div>
              </div>
              <div className="mono text-xl font-bold text-[var(--lime)]">{p.lastGrade || '—'}</div>
            </div>
          </Link>
        ))}
        {projects.length === 0 && <p className="text-[var(--mut)]">No projects yet.</p>}
      </div>
    </div>
  );
}
