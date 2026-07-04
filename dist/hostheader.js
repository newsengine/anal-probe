// src/hostheader.ts
// Host-header injection probe. Many apps build absolute URLs (password-reset links, redirects, canonical
// tags, cached responses) from the incoming Host / X-Forwarded-Host header. If an attacker-controlled host
// is reflected back, that enables password-reset poisoning (the reset link points at the attacker) and
// web-cache poisoning. This sends ONE extra request with a spoofed X-Forwarded-Host (and friends) and checks
// whether the marker host is reflected in the body's absolute URLs or a redirect Location. Non-destructive:
// a single GET with request headers; nothing is written.
import { safeFetch } from './core.js';
const f = (id, title, severity, pass, detail, fix) => ({ category: 'security', id, title, severity, pass, detail, fix });
const MARKER = 'anal-probe-hhi.example';
export async function hostHeaderChecks(ctx) {
    // Host itself is a forbidden fetch header, but the reverse-proxy overrides are the real-world vector.
    const spoof = { 'X-Forwarded-Host': MARKER, 'X-Forwarded-Server': MARKER, 'X-Host': MARKER, 'Forwarded': `host=${MARKER}` };
    let res = null;
    try {
        res = await safeFetch(ctx.origin, { headers: spoof, redirect: 'manual' });
    }
    catch { /* network hiccup — stay silent rather than false-flag */ }
    if (!res)
        return [];
    const loc = res.headers.get('location') || '';
    const link = res.headers.get('link') || '';
    const body = res.status < 400 && (res.headers.get('content-type') || '').includes('html')
        ? await res.text().then((t) => t.slice(0, 200_000)).catch(() => '')
        : '';
    // Reflection in a redirect target is the strongest signal (reset-poisoning / open-redirect-by-host).
    const inRedirect = new RegExp(`https?://${MARKER.replace('.', '\\.')}`, 'i').test(loc);
    // Reflection in an absolute URL in the body (canonical/og:url/reset link built from the host).
    const inBody = new RegExp(`https?://${MARKER.replace('.', '\\.')}`, 'i').test(body) || new RegExp(MARKER.replace('.', '\\.')).test(link);
    if (inRedirect || inBody) {
        return [f('host-header.injection', 'Host header is reflected into URLs (Host-header injection)', 'medium', false, `a spoofed X-Forwarded-Host (${MARKER}) was reflected into ${inRedirect ? 'the redirect Location' : 'an absolute URL in the response'} — this enables password-reset-link poisoning and web-cache poisoning`, 'Never build absolute URLs from the incoming Host/X-Forwarded-Host. Use a configured canonical base URL, and validate Host against an allow-list at the edge.')];
    }
    return [f('host-header.injection', 'Host header is not reflected into URLs', 'medium', true, `a spoofed X-Forwarded-Host was not reflected into redirects or absolute URLs`, undefined)];
}
