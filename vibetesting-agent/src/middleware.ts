import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Security headers + per-request CSP nonce.
 * Next.js App Router reads `x-nonce` from the request and stamps it on its
 * own scripts — so we can drop 'unsafe-inline' / 'unsafe-eval' on script-src.
 */
function buildCsp(nonce: string): string {
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    // Nonce + strict-dynamic: trusted scripts may load children; no eval/inline
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    // Styles still need unsafe-inline for Next/Tailwind runtime style tags
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "font-src 'self' data:",
    [
      "connect-src 'self'",
      'https://api.stripe.com',
      'https://checkout.stripe.com',
      'https://billing.stripe.com',
      'https://*.workos.com',
      'https://workoscdn.com',
      'https://cloudflare-dns.com',
    ].join(' '),
    "form-action 'self' https://checkout.stripe.com https://billing.stripe.com https://*.workos.com",
    "frame-src 'self' https://checkout.stripe.com https://billing.stripe.com https://*.workos.com",
    'upgrade-insecure-requests',
  ].join('; ');
}

const BASE_SECURITY_HEADERS: Record<string, string> = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-site',
  'X-DNS-Prefetch-Control': 'off',
};

function makeNonce(): string {
  // URL-safe base64 from 16 random bytes (Workers + Node compatible)
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function middleware(req: NextRequest) {
  const nonce = makeNonce();
  const csp = buildCsp(nonce);

  // Force HTTPS when Cloudflare/proxy still delivers http://
  const proto = req.headers.get('x-forwarded-proto');
  if (proto === 'http') {
    const httpsUrl = req.nextUrl.clone();
    httpsUrl.protocol = 'https:';
    const redirect = NextResponse.redirect(httpsUrl, 308);
    for (const [k, v] of Object.entries(BASE_SECURITY_HEADERS)) {
      redirect.headers.set(k, v);
    }
    redirect.headers.set('Content-Security-Policy', csp);
    return redirect;
  }

  // Pass nonce to Next so framework scripts get nonce="…"
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set('x-nonce', nonce);

  const res = NextResponse.next({
    request: { headers: requestHeaders },
  });
  for (const [k, v] of Object.entries(BASE_SECURITY_HEADERS)) {
    res.headers.set(k, v);
  }
  res.headers.set('Content-Security-Policy', csp);
  // Optional: expose nonce for debugging / client scripts that opt in
  res.headers.set('x-nonce', nonce);
  return res;
}

export const config = {
  matcher: [
    /*
     * Match all paths except static media maps that break under over-strict CSP.
     * Still apply headers to pages, API, and most assets.
     */
    '/((?!_next/static/media|_next/static/chunks/.*\\.map$).*)',
  ],
};
