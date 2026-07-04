// src/csrf.ts
// CSRF-protection heuristic. A classic gap: a state-changing HTML <form method="post"> that carries no
// anti-CSRF token, on a site whose session cookie isn't SameSite-protected, lets any other site submit it
// on the victim's behalf. Deliberately CONSERVATIVE to keep false positives ~zero:
//   - only considers real POST forms (SPA forms that preventDefault() default to GET, so they're skipped);
//   - treats a hidden token field OR a <meta name="csrf-token"> OR SameSite=Lax/Strict on the session
//     cookie as protection (any one clears it);
//   - only when a POST form has NO token AND the session cookie is not SameSite-protected is it a finding.
// Black-box: parses the homepage HTML + Set-Cookie. No requests, nothing submitted.
const f = (id, title, severity, pass, detail, fix) => ({ category: 'security', id, title, severity, pass, detail, fix });
// Hidden field names frameworks use for CSRF tokens (Rails/Django/Laravel/ASP.NET/Express-csurf/etc.).
const TOKEN_FIELD = /<input\b[^>]*name=["'][^"']*(?:csrf|xsrf|_token|authenticity_token|__requestverificationtoken|nonce|anti-?forgery)[^"']*["']/i;
const TOKEN_META = /<meta\b[^>]*name=["'](?:csrf-token|_csrf|xsrf-token|csrf-param)["']/i;
const SESSION_COOKIE = /^(?:.*(?:session|sess|auth|sid|token|jwt|csrf).*)$/i;
function getSetCookies(headers) {
    const anyH = headers;
    if (typeof anyH.getSetCookie === 'function')
        return anyH.getSetCookie();
    const one = headers.get('set-cookie');
    return one ? [one] : [];
}
export function csrfFindings(ctx) {
    const html = ctx.html;
    if (!html)
        return [];
    const forms = [...html.matchAll(/<form\b[^>]*>[\s\S]*?<\/form>/gi)].map((m) => m[0]);
    const postForms = forms.filter((fm) => /<form\b[^>]*\bmethod\s*=\s*["']?\s*post/i.test(fm));
    if (!postForms.length)
        return []; // no state-changing HTML forms (SPA/header-token apps) → not applicable
    const metaToken = TOKEN_META.test(html);
    const unprotectedForms = postForms.filter((fm) => !metaToken && !TOKEN_FIELD.test(fm));
    // SameSite=Lax/Strict on the session cookie mitigates cross-site form submission at the browser.
    const sessionCookie = getSetCookies(ctx.headers).find((c) => SESSION_COOKIE.test((c.split('=')[0] || '').trim()));
    const sameSiteProtected = !!sessionCookie && /;\s*samesite\s*=\s*(lax|strict)/i.test(sessionCookie);
    if (!unprotectedForms.length) {
        return [f('csrf', 'POST forms carry a CSRF token', 'medium', true, `${postForms.length} POST form(s); a CSRF token field or meta tag is present`, undefined)];
    }
    if (sameSiteProtected) {
        return [f('csrf', 'POST form has no CSRF token (mitigated by SameSite cookie)', 'low', false, `${unprotectedForms.length} POST form(s) lack a CSRF token, but the session cookie is SameSite=${/strict/i.test(sessionCookie) ? 'Strict' : 'Lax'} which blocks most cross-site submits — add a token for defense-in-depth`, 'Add a per-request anti-CSRF token (synchronizer token or double-submit cookie) to state-changing forms; SameSite alone is not a complete defense.')];
    }
    return [f('csrf', `${unprotectedForms.length} POST form(s) without CSRF protection`, 'medium', false, `state-changing POST form(s) have no anti-CSRF token${sessionCookie ? ' and the session cookie is not SameSite=Lax/Strict' : ''} — another site could submit them on a logged-in victim's behalf`, 'Add a per-request anti-CSRF token to every state-changing form and verify it server-side; also set SameSite=Lax (or Strict) on session cookies.')];
}
