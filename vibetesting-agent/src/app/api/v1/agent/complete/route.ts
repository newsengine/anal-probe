import { z } from 'zod';
import { json, errorResponse, readJson, clientIp } from '@/lib/http';
import { config } from '@/lib/config';
import { completeAgentScan } from '@/lib/scans';
import { agentAuthBearer, verifyAgentPayload } from '@/lib/agent-crypto';
import { audit } from '@/lib/audit';

const schema = z.object({
  scanId: z.string().min(1),
  agentId: z.string().min(1),
  /** Unix ms — reject if older than 10 minutes (replay) */
  ts: z.number().int().positive(),
  score: z.number().optional(),
  grade: z.string().optional(),
  summary: z
    .object({
      total: z.number(),
      passed: z.number(),
      failed: z.number(),
      failHigh: z.number(),
      failMedium: z.number(),
      failLow: z.number(),
    })
    .optional(),
  findings: z.array(z.any()).optional(),
  fixPackMarkdown: z.string().optional(),
  reportHtml: z.string().optional(),
  baselineDiff: z.any().optional(),
  error: z.string().optional(),
  /** HMAC-SHA256 (base64url) of canonical payload without `signature` field */
  signature: z.string().min(16),
});

/** OVH agent posts full vibetesting-agent results — must be HMAC-signed. */
export async function POST(req: Request) {
  try {
    if (!agentAuthBearer(req, config.scanAgentSecret)) return json({ error: 'Unauthorized' }, 401);
    const body = schema.parse(await readJson(req));

    const age = Math.abs(Date.now() - body.ts);
    if (age > 10 * 60 * 1000) {
      return json({ error: 'Stale agent payload (ts)' }, 401);
    }

    const { signature, ...unsigned } = body;
    const ok = await verifyAgentPayload(config.scanAgentSecret, unsigned, signature);
    if (!ok) {
      await audit('agent.complete.bad_sig', {
        target: body.scanId,
        detail: { agentId: body.agentId },
        ip: clientIp(req),
      });
      return json({ error: 'Invalid signature' }, 401);
    }

    if (!body.error && (!body.findings || body.score == null || !body.grade || !body.summary)) {
      return json({ error: 'findings, score, grade, summary required unless error is set' }, 400);
    }

    const scan = await completeAgentScan(body.scanId, {
      agentId: body.agentId,
      score: body.score ?? 0,
      grade: body.grade ?? 'F',
      summary: body.summary ?? {
        total: 0,
        passed: 0,
        failed: 0,
        failHigh: 0,
        failMedium: 0,
        failLow: 0,
      },
      findings: body.findings || [],
      fixPackMarkdown: body.fixPackMarkdown,
      reportHtml: body.reportHtml,
      baselineDiff: body.baselineDiff,
      error: body.error,
    });
    if (!scan) return json({ error: 'Scan not found' }, 404);
    return json({ ok: true, status: scan.status, score: scan.score, grade: scan.grade });
  } catch (err) {
    return errorResponse(err);
  }
}
