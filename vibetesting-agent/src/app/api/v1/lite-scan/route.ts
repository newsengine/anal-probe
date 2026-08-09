/**
 * Public lite scan — no auth required.
 * Strict rate limits + authorization checkbox + SSRF URL filter.
 * Supports streaming NDJSON progress when body.stream === true.
 */
import { z } from 'zod';
import { json, errorResponse, readJson, clientIp } from '@/lib/http';
import { rateLimit } from '@/lib/rate-limit';
import { runScan, buildAgentFixPrompt, type ScanProgressEvent, type Finding } from '@/lib/scanner';
import { LITE_CATEGORIES } from '@/lib/plans';
import { audit } from '@/lib/audit';
import { assertSafeScanUrl } from '@/lib/url-safety';

const schema = z.object({
  url: z.string().min(3).max(500),
  authorized: z.literal(true),
  stream: z.boolean().optional(),
});

function buildLitePayload(result: Awaited<ReturnType<typeof runScan>>) {
  const liteSet = new Set<string>(LITE_CATEGORIES as unknown as string[]);
  const findings = result.findings
    .filter((f) => liteSet.has(f.category) || !f.pass)
    .slice(0, 40)
    .map((f) => ({
      id: f.id,
      category: f.category,
      title: f.title,
      severity: f.severity,
      pass: f.pass,
      detail: f.detail.slice(0, 280),
      fix: f.fix?.slice(0, 200),
    }));

  const failed = findings.filter((f) => !f.pass);

  // Findings for the Claude/Codex prompt — lite categories + any high/medium
  const agentFindings: Finding[] = result.findings
    .filter((f) => !f.pass)
    .filter((f) => liteSet.has(f.category) || f.severity === 'high' || f.severity === 'medium')
    .slice(0, 40);

  const agentPrompt = buildAgentFixPrompt(result.url, agentFindings, result.score, result.grade, {
    suite: 'VibeTesting Agent free lite scan (secrets · exposure · security · DNS)',
  });

  // Teaser for anonymous users: structure + first issue only
  const previewLines = agentPrompt.split('\n').slice(0, 18).join('\n');
  const agentPromptPreview =
    failed.length > 0
      ? `${previewLines}\n\n… +${Math.max(0, failed.length - 1)} more ranked fixes in the full Claude/Codex prompt.\n\n→ Create a free account to unlock the complete prompt for this website.`
      : agentPrompt;

  return {
    lite: true as const,
    url: result.url,
    score: result.score,
    grade: result.grade,
    summary: {
      checked: findings.length,
      failed: failed.length,
      high: failed.filter((f) => f.severity === 'high').length,
      medium: failed.filter((f) => f.severity === 'medium').length,
    },
    findings: failed.slice(0, 12),
    /** Full agent brief — also returned so account UX can copy after signup via client storage */
    agentPrompt,
    agentPromptPreview,
    issueCount: failed.length,
    upgrade: {
      message:
        failed.length > 0
          ? `Create a free account to unlock the full Claude/Codex fix prompt for ${new URL(result.url).hostname} (${failed.length} issue${failed.length === 1 ? '' : 's'} ranked P1→Pn).`
          : 'Create a free account to save scans, verify ownership, and unlock the full suite.',
      headline: failed.length > 0 ? 'Get your Claude / Codex fix prompt' : 'Save this clean scan',
      plans: [
        { id: 'weekly', price: 25, label: '1 full scan / week' },
        { id: 'daily', price: 100, label: 'Daily full scans' },
        { id: 'commit', price: 250, label: 'Scan on every commit' },
      ],
      cta: '/login',
      ctaLabel: 'Create free account',
    },
  };
}

export async function POST(req: Request) {
  try {
    const ip = clientIp(req);
    const rl = await rateLimit(`lite:${ip}`, 5, 60 * 60 * 1000); // 5/hour/IP
    if (!rl.ok) {
      return json(
        { error: 'Lite scan rate limit reached. Create a free account or upgrade for more.' },
        429,
      );
    }

    const body = schema.parse(await readJson(req));
    const safe = assertSafeScanUrl(body.url);
    if (!safe.ok) {
      return json({ error: `That target cannot be scanned: ${safe.reason}` }, 400);
    }
    const url = safe.url;

    await audit('lite_scan', { target: url, ip, detail: { host: safe.hostname, stream: !!body.stream } });

    if (!body.stream) {
      const result = await runScan(url, { mode: 'fast', forceWorker: true });
      return json(buildLitePayload(result));
    }

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      async start(controller) {
        const write = (obj: unknown) => {
          controller.enqueue(encoder.encode(JSON.stringify(obj) + '\n'));
        };

        try {
          write({
            type: 'meta',
            message: `Authorized lite scan · rate-limited · SSRF-filtered`,
            suite: ['secrets', 'exposure', 'security', 'dns'],
          });

          const result = await runScan(url, {
            mode: 'fast',
            forceWorker: true,
            onProgress: async (event: ScanProgressEvent) => {
              write(event);
            },
          });

          write({ type: 'result', ...buildLitePayload(result) });
        } catch (err) {
          write({
            type: 'error',
            error: err instanceof Error ? err.message : 'Scan failed',
          });
        } finally {
          controller.close();
        }
      },
    });

    return new Response(stream, {
      status: 200,
      headers: {
        'Content-Type': 'application/x-ndjson; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch (err) {
    return errorResponse(err);
  }
}
