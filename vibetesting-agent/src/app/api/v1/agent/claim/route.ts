import { json, errorResponse, clientIp } from '@/lib/http';
import { config } from '@/lib/config';
import { claimNextScan } from '@/lib/scans';
import { audit } from '@/lib/audit';
import { agentAuthBearer } from '@/lib/agent-crypto';
import { getDb, schema } from '@/lib/db';
import { eq } from 'drizzle-orm';
import { resolveAuthHeaders } from '@/lib/project-auth';

/** OVH scan agent polls this to claim the next full scan job. */
export async function POST(req: Request) {
  try {
    if (!agentAuthBearer(req, config.scanAgentSecret)) return json({ error: 'Unauthorized' }, 401);
    const body = (await req.json().catch(() => ({}))) as { agentId?: string };
    const agentId = body.agentId || `agent-${clientIp(req)}`;
    const scan = await claimNextScan(agentId);
    if (!scan) return json({ job: null });

    // Optional authenticated session for same-origin probe (never logged)
    let authHeaders: Record<string, string> | null = null;
    if (scan.projectId) {
      const db = await getDb();
      const prows = await db
        .select()
        .from(schema.projects)
        .where(eq(schema.projects.id, scan.projectId))
        .limit(1);
      if (prows[0]) authHeaders = await resolveAuthHeaders(prows[0]);
    }

    await audit('agent.claim', {
      target: scan.id,
      detail: {
        agentId,
        url: scan.url,
        mode: scan.mode,
        authenticated: Boolean(authHeaders),
      },
      ip: clientIp(req),
    });
    return json({
      job: {
        id: scan.id,
        url: scan.url,
        mode: scan.mode,
        projectId: scan.projectId,
        /** Same-origin Cookie / Authorization for vibetesting-agent --cookie / --header */
        authHeaders: authHeaders || undefined,
      },
    });
  } catch (err) {
    return errorResponse(err);
  }
}
