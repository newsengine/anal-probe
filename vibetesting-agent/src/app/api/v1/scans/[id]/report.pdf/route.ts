/**
 * GET /api/v1/scans/:id/report.pdf
 * PDF security-review report generated at end of each completed scan.
 */
import { resolveRequestUser, AuthError } from '@/lib/auth';
import { getScanForUser, parseFindings } from '@/lib/scans';
import { buildSecurityReviewPdf } from '@/lib/security-review';
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
    const pdf = buildSecurityReviewPdf(
      scan.url,
      findings,
      scan.score ?? 0,
      scan.grade ?? '?',
      {
        mode: scan.mode,
        scanId: scan.id,
        suite: `VibeTesting Agent ${scan.mode} suite`,
      },
    );

    const host = (() => {
      try {
        return new URL(scan.url).hostname;
      } catch {
        return 'scan';
      }
    })();
    const filename = `security-review-${host}-${scan.id}.pdf`;

    // Copy into a plain ArrayBuffer for BodyInit compatibility (Workers + Node)
    const body = pdf.buffer.slice(pdf.byteOffset, pdf.byteOffset + pdf.byteLength) as ArrayBuffer;
    return new Response(body, {
      status: 200,
      headers: {
        'content-type': 'application/pdf',
        'content-disposition': `attachment; filename="${filename}"`,
        'content-length': String(pdf.byteLength),
        'cache-control': 'private, no-store',
      },
    });
  } catch (err) {
    return errorResponse(err);
  }
}
