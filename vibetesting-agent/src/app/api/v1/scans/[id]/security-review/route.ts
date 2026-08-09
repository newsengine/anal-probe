/**
 * GET /api/v1/scans/:id/security-review
 * Claude `/security-review` markdown (download or JSON).
 *   ?format=md   → text/markdown attachment (default for Accept: text/markdown)
 *   ?format=json → { markdown, grade, score, url }
 */
import { resolveRequestUser, AuthError } from '@/lib/auth';
import { getScanForUser, parseFindings } from '@/lib/scans';
import { buildFixPack } from '@/lib/scanner';
import { json, errorResponse } from '@/lib/http';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { id } = await ctx.params;
    const scan = await getScanForUser(id, user.id);
    if (!scan) return json({ error: 'Not found' }, 404);
    if (scan.status !== 'completed') {
      return json({ error: 'Scan not completed yet', status: scan.status }, 409);
    }

    const findings = parseFindings(scan);
    const markdown =
      scan.fixPackMarkdown ||
      buildFixPack(scan.url, findings, scan.score ?? 0, scan.grade ?? '?', {
        mode: scan.mode,
        scanId: scan.id,
      });

    const url = new URL(req.url);
    const format = (url.searchParams.get('format') || '').toLowerCase();
    const wantMd =
      format === 'md' ||
      format === 'markdown' ||
      (req.headers.get('accept') || '').includes('text/markdown');

    if (wantMd) {
      const host = (() => {
        try {
          return new URL(scan.url).hostname;
        } catch {
          return 'scan';
        }
      })();
      const filename = `security-review-${host}-${scan.id}.md`;
      return new Response(markdown, {
        status: 200,
        headers: {
          'content-type': 'text/markdown; charset=utf-8',
          'content-disposition': `attachment; filename="${filename}"`,
          'cache-control': 'private, no-store',
        },
      });
    }

    return json({
      format: 'claude-/security-review',
      scanId: scan.id,
      url: scan.url,
      grade: scan.grade,
      score: scan.score,
      mode: scan.mode,
      markdown,
      download: {
        markdown: `/api/v1/scans/${scan.id}/security-review?format=md`,
        pdf: `/api/v1/scans/${scan.id}/report.pdf`,
      },
    });
  } catch (err) {
    return errorResponse(err);
  }
}
