import { eq, desc, and } from 'drizzle-orm';
import { getProjectByShareToken } from '@/lib/projects';
import { getDb, schema } from '@/lib/db';
import { planOf } from '@/lib/plans';
import { json } from '@/lib/http';

export async function GET(_req: Request, ctx: { params: Promise<{ shareToken: string }> }) {
  const { shareToken } = await ctx.params;
  const project = await getProjectByShareToken(shareToken);
  if (!project) return json({ error: 'Not found' }, 404);

  const db = await getDb();
  const users = await db.select().from(schema.users).where(eq(schema.users.id, project.userId)).limit(1);
  const user = users[0];
  const plan = planOf(user?.plan);

  const scans = await db
    .select()
    .from(schema.scans)
    .where(and(eq(schema.scans.projectId, project.id), eq(schema.scans.status, 'completed')))
    .orderBy(desc(schema.scans.createdAt))
    .limit(1);

  const scan = scans[0];
  if (!scan) {
    return json({
      project: { name: project.name, url: project.url, grade: null, score: null },
      expired: false,
    });
  }

  // Free plan shares expire after retentionDays
  if (!plan.sharePermanent && scan.finishedAt) {
    const age = Date.now() - scan.finishedAt.getTime();
    if (age > plan.retentionDays * 24 * 60 * 60 * 1000) {
      return json({ error: 'Share link expired', expired: true }, 410);
    }
  }

  return json({
    project: {
      name: project.name,
      url: project.url,
      grade: project.lastGrade,
      score: project.lastScore,
    },
    scan: {
      id: scan.id,
      grade: scan.grade,
      score: scan.score,
      summary: scan.summaryJson ? JSON.parse(scan.summaryJson) : null,
      finishedAt: scan.finishedAt,
      reportHtml: scan.reportHtml,
    },
    expired: false,
  });
}
