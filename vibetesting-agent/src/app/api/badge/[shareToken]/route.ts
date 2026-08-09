import { getProjectByShareToken } from '@/lib/projects';

export async function GET(_req: Request, ctx: { params: Promise<{ shareToken: string }> }) {
  const { shareToken } = await ctx.params;
  const project = await getProjectByShareToken(shareToken);
  if (!project || !project.badgePublic) {
    return new Response(badgeSvg('VibeTesting Agent', 'private', '#6b7280'), {
      headers: {
        'content-type': 'image/svg+xml',
        'cache-control': 'public, max-age=60',
      },
    });
  }
  const grade = project.lastGrade || '?';
  const score = project.lastScore ?? '—';
  const color =
    grade === 'A' ? '#16a34a' : grade === 'B' ? '#65a30d' : grade === 'C' ? '#ca8a04' : grade === 'D' ? '#ea580c' : '#dc2626';
  return new Response(badgeSvg('ship score', `${grade} ${score}`, color), {
    headers: {
      'content-type': 'image/svg+xml',
      'cache-control': 'public, max-age=120',
    },
  });
}

function badgeSvg(label: string, value: string, color: string) {
  const lw = 11 * label.length + 10;
  const vw = 11 * String(value).length + 14;
  const w = lw + vw;
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${label}: ${value}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lw}" height="20" fill="#555"/>
    <rect x="${lw}" width="${vw}" height="20" fill="${color}"/>
    <rect width="${w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="${lw / 2}" y="14">${escapeXml(label)}</text>
    <text x="${lw + vw / 2}" y="14">${escapeXml(String(value))}</text>
  </g>
</svg>`;
}

function escapeXml(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]!);
}
