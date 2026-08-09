import Link from 'next/link';
import { getProjectByShareToken } from '@/lib/projects';
import { getDb, schema } from '@/lib/db';
import { eq, desc, and } from 'drizzle-orm';
import { planOf } from '@/lib/plans';

export default async function SharePage({ params }: { params: Promise<{ shareToken: string }> }) {
  const { shareToken } = await params;
  const project = await getProjectByShareToken(shareToken);
  if (!project) {
    return (
      <div className="mx-auto max-w-lg px-6 py-20 text-center">
        <h1 className="mono text-2xl font-bold">Not found</h1>
        <Link href="/" className="mt-4 inline-block text-[var(--lime)]">
          VibeTesting Agent
        </Link>
      </div>
    );
  }

  const db = await getDb();
  const users = await db.select().from(schema.users).where(eq(schema.users.id, project.userId)).limit(1);
  const plan = planOf(users[0]?.plan);
  const scans = await db
    .select()
    .from(schema.scans)
    .where(and(eq(schema.scans.projectId, project.id), eq(schema.scans.status, 'completed')))
    .orderBy(desc(schema.scans.createdAt))
    .limit(1);
  const scan = scans[0];

  if (scan?.finishedAt && !plan.sharePermanent) {
    const age = Date.now() - scan.finishedAt.getTime();
    if (age > plan.retentionDays * 86400000) {
      return (
        <div className="mx-auto max-w-lg px-6 py-20 text-center">
          <h1 className="mono text-2xl font-bold">Share expired</h1>
          <p className="mt-2 text-[var(--mut)]">Upgrade to Vibe for permanent share links.</p>
        </div>
      );
    }
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-12">
      <div className="mono text-sm text-[var(--lime)]">VibeTesting Agent public report</div>
      <h1 className="mono mt-2 text-3xl font-bold">{project.name}</h1>
      <p className="mono text-[var(--mut)]">{project.url}</p>
      <div className="mt-8 flex gap-8">
        <div>
          <div className="text-xs uppercase text-[var(--mut)]">Grade</div>
          <div className="mono text-5xl font-extrabold text-[var(--lime)]">{project.lastGrade || '—'}</div>
        </div>
        <div>
          <div className="text-xs uppercase text-[var(--mut)]">Score</div>
          <div className="mono text-5xl font-extrabold">{project.lastScore ?? '—'}</div>
        </div>
      </div>
      {scan?.reportHtml && (
        <iframe
          title="report"
          className="mt-10 h-[640px] w-full rounded-xl border border-[var(--edge)] bg-white"
          srcDoc={scan.reportHtml}
        />
      )}
      <p className="mt-8 text-center text-xs text-[var(--mut)]">
        Hygiene scan only — not a pentest. Authorized use required.
      </p>
    </div>
  );
}
