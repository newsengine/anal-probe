// src/jwt.ts
// JWT hygiene checks. A real review inspects any JSON Web Token the app hands the browser — the classic
// findings are `alg:none` (unsigned → trivial forgery/auth-bypass), tokens with no expiry, absurdly long
// lifetimes, and session tokens sitting in a script-readable (non-HttpOnly) cookie so any XSS steals them.
// This finds JWTs in Set-Cookie, response headers, and the HTML/inline JS, decodes the header+payload
// (base64url — NO signature verification, black-box), and flags the weak patterns. Zero-dependency.
const f = (id, title, severity, pass, detail, fix) => ({ category: 'security', id, title, severity, pass, detail, fix });
// Three base64url segments; header segment starts with `eyJ` (== `{"` base64url), which is what makes a JWT
// recognisable without decoding. Signature may be empty (alg:none).
const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/g;
export function b64urlDecode(seg) {
    const b64 = seg.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((seg.length + 3) % 4);
    try {
        return Buffer.from(b64, 'base64').toString('utf8');
    }
    catch {
        return '';
    }
}
const SENSITIVE_CLAIM = /^(email|role|roles|is_?admin|admin|password|ssn|scope|permissions?|user_?name)$/i;
// Decode (do NOT verify) a JWT. Pure + testable; `now` lets callers assert expiry deterministically.
export function analyzeJwt(token) {
    const parts = token.split('.');
    if (parts.length !== 3)
        return { valid: false, hasExp: false, sensitiveClaims: [] };
    let header = null, claims = null;
    try {
        header = JSON.parse(b64urlDecode(parts[0]));
    }
    catch { /* not a JWT */ }
    try {
        claims = JSON.parse(b64urlDecode(parts[1]));
    }
    catch { /* opaque payload */ }
    if (!header || typeof header !== 'object')
        return { valid: false, hasExp: false, sensitiveClaims: [] };
    const alg = typeof header.alg === 'string' ? header.alg : undefined;
    const c = claims && typeof claims === 'object' ? claims : {};
    const hasExp = typeof c.exp === 'number';
    const lifetimeDays = hasExp && typeof c.iat === 'number' ? Math.round((c.exp - c.iat) / 86400) : undefined;
    const sensitiveClaims = Object.keys(c).filter((k) => SENSITIVE_CLAIM.test(k));
    return { valid: true, alg, header, claims: c, hasExp, expSeconds: hasExp ? c.exp : undefined, lifetimeDays, sensitiveClaims };
}
// Was a given token seen in a Set-Cookie without HttpOnly? (script-readable session token)
function tokenInNonHttpOnlyCookie(token, setCookies) {
    return setCookies.some((sc) => sc.includes(token.slice(0, 24)) && !/;\s*httponly/i.test(sc));
}
export function jwtFindings(ctx) {
    const out = [];
    // Gather candidate tokens from headers + document.
    const setCookies = typeof ctx.headers.getSetCookie === 'function'
        ? ctx.headers.getSetCookie()
        : (ctx.headers.get('set-cookie') ? [ctx.headers.get('set-cookie')] : []);
    const haystack = [ctx.html, setCookies.join('\n'), ctx.headers.get('authorization') || ''].join('\n');
    const tokens = [...new Set((haystack.match(JWT_RE) || []))].filter((t) => analyzeJwt(t).valid);
    if (!tokens.length)
        return out; // JWTs are optional; stay silent when none are exposed to the browser
    let anyIssue = false;
    for (const token of tokens) {
        const a = analyzeJwt(token);
        const label = (a.claims?.sub ? `sub=${String(a.claims.sub).slice(0, 24)}` : `alg=${a.alg}`);
        if ((a.alg || '').toLowerCase() === 'none') {
            anyIssue = true;
            out.push(f('jwt.alg-none', 'JWT uses alg:none (unsigned)', 'high', false, `an exposed JWT (${label}) has header alg:"none" — unsigned tokens can be forged to impersonate any user`, 'Reject alg:none server-side; require a fixed strong algorithm (e.g. RS256/EdDSA) and verify the signature on every request.'));
        }
        if (!a.hasExp) {
            anyIssue = true;
            out.push(f('jwt.no-exp', 'JWT has no expiry (exp) claim', 'medium', false, `an exposed JWT (${label}) has no exp claim — a leaked token is valid forever`, 'Always set a short exp on tokens and reject tokens without one; use refresh tokens for longer sessions.'));
        }
        else if ((a.lifetimeDays ?? 0) > 7) {
            anyIssue = true;
            out.push(f('jwt.long-lived', `JWT lifetime is ${a.lifetimeDays} days`, 'low', false, `an exposed JWT (${label}) lives ${a.lifetimeDays} days — a stolen token stays usable that long`, 'Shorten access-token lifetime (minutes–hours) and rotate via refresh tokens.'));
        }
        if (tokenInNonHttpOnlyCookie(token, setCookies)) {
            anyIssue = true;
            out.push(f('jwt.cookie-not-httponly', 'JWT stored in a non-HttpOnly cookie', 'medium', false, `a JWT is set in a cookie without HttpOnly — any XSS on the site can read and exfiltrate the session token`, 'Set HttpOnly (and Secure + SameSite) on the session cookie so scripts can\'t read the token.'));
        }
        if (a.sensitiveClaims.length) {
            out.push(f('jwt.sensitive-claims', 'JWT payload carries sensitive claims', 'info', true, `the token's payload (base64, readable by anyone) contains: ${a.sensitiveClaims.join(', ')} — JWT payloads are NOT encrypted`, 'Confirm these are non-secret; never put passwords/secrets in a JWT payload (it\'s only base64-encoded).'));
        }
    }
    if (!anyIssue)
        out.push(f('jwt.ok', 'Exposed JWT(s) look hygienic', 'info', true, `${tokens.length} JWT(s) seen; signed with an explicit alg, all have exp, none over-long`, undefined));
    return out;
}
