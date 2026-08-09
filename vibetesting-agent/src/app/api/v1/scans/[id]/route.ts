import { resolveRequestUser, AuthError } from '@/lib/auth';
import { getScanForUser, parseFindings } from '@/lib/scans';
import { json, errorResponse } from '@/lib/http';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const scan = await getScanForUser(id, user.id);
    if (!scan) return json({ error: 'Not found' }, 404);

    const findings = parseFindings(scan);
    let summary = null;
    let baselineDiff = null;
    try {
      summary = scan.summaryJson ? JSON.parse(scan.summaryJson) : null;
    } catch { /* */ }
    try {
      baselineDiff = scan.baselineDiffJson ? JSON.parse(scan.baselineDiffJson) : null;
    } catch { /* */ }

    return json({
      scan: {
        id: scan.id,
        projectId: scan.projectId,
        url: scan.url,
        mode: scan.mode,
        trigger: scan.trigger,
        status: scan.status,
        score: scan.score,
        grade: scan.grade,
        summary,
        findings,
        baselineDiff,
        fixPackMarkdown: scan.fixPackMarkdown,
        error: scan.error,
        createdAt: scan.createdAt,
        startedAt: scan.startedAt,
        finishedAt: scan.finishedAt,
      },
    });
  } catch (err) {
    return errorResponse(err);
  }
}
