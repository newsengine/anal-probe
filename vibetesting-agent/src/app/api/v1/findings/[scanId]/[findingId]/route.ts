import { resolveRequestUser, AuthError } from '@/lib/auth';
import { getScanForUser, parseFindings } from '@/lib/scans';
import { json, errorResponse } from '@/lib/http';

export async function GET(req: Request, ctx: { params: Promise<{ scanId: string; findingId: string }> }) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();
    const { scanId, findingId } = await ctx.params;
    const scan = await getScanForUser(scanId, user.id);
    if (!scan) return json({ error: 'Not found' }, 404);
    const findings = parseFindings(scan);
    const finding = findings.find((f) => f.id === findingId);
    if (!finding) return json({ error: 'Finding not found' }, 404);
    return json({ finding, scanId, url: scan.url });
  } catch (err) {
    return errorResponse(err);
  }
}
