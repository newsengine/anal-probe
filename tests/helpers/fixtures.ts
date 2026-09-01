/**
 * known-bad / known-good fixture servers for end-to-end probe coverage.
 */
import type http from 'node:http';
import {
  startServer,
  send,
  EXPOSURE_BODIES,
  HARDENED_HEADERS,
  CLEAN_HTML,
  LEAKY_HTML,
  type FixtureServer,
} from './http-fixture.ts';

/** Deliberately insecure app: secrets, exposure paths, open redirect, weak HTML. */
export async function startKnownBad(): Promise<FixtureServer> {
  const handler: http.RequestListener = (req, res) => {
    const url = new URL(req.url || '/', 'http://fixture.local');
    const path = url.pathname;

    // Open redirect for securityChecks
    const next = url.searchParams.get('next') || url.searchParams.get('redirect');
    if (next) {
      res.writeHead(302, { location: next });
      res.end();
      return;
    }

    if (path === '/.well-known/security.txt') {
      send(res, 404, 'not found');
      return;
    }

    if (path === '/robots.txt') {
      send(res, 200, 'User-agent: *\nDisallow: /admin\nDisallow: /.env\n', {
        'content-type': 'text/plain',
      });
      return;
    }

    if (path in EXPOSURE_BODIES) {
      const item = EXPOSURE_BODIES[path]!;
      send(res, 200, item.body, { 'content-type': item.type });
      return;
    }

    // #24 API-surface fixtures ------------------------------------------------
    // Unauthenticated data leak + dangerous CORS reflection (echoes any Origin with credentials).
    if (path === '/api/config') {
      const origin = req.headers.origin as string | undefined;
      send(
        res,
        200,
        JSON.stringify({ apiKey: 'pk_test_x', users: [{ id: 1, email: 'a@b.com' }], featureFlags: { beta: true } }),
        {
          'content-type': 'application/json',
          ...(origin ? { 'access-control-allow-origin': origin, 'access-control-allow-credentials': 'true' } : {}),
        },
      );
      return;
    }
    // Expensive LLM-ish endpoint with no throttling (for the opt-in rate-limit scan).
    if (path === '/api/ai/checklist') {
      send(res, 200, JSON.stringify({ items: [1, 2, 3] }), { 'content-type': 'application/json' });
      return;
    }
    // Accepts an unauthenticated write (for the opt-in write probe).
    if (path === '/api/sync' && req.method === 'POST') {
      send(res, 200, JSON.stringify({ ok: true }), { 'content-type': 'application/json' });
      return;
    }
    // Reflected input echoed unencoded into HTML (for the opt-in reflected-XSS probe).
    const reflected = url.searchParams.get('q') || url.searchParams.get('search') || url.searchParams.get('s');
    if (reflected) {
      send(res, 200, `<!DOCTYPE html><html><body><h1>Results for ${reflected}</h1></body></html>`, {
        'content-type': 'text/html',
      });
      return;
    }

    // Directory listing for one common path
    if (path === '/uploads/' || path === '/uploads') {
      send(
        res,
        200,
        '<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1><pre><a href="../">Parent Directory</a>\n<a href="secret.txt">secret.txt</a></pre></body></html>',
        { 'content-type': 'text/html' },
      );
      return;
    }

    // Broken link / image targets → 404
    if (path === '/broken-link' || path === '/broken-image.png') {
      send(res, 404, 'missing');
      return;
    }

    send(res, 200, LEAKY_HTML, { 'content-type': 'text/html' });
  };

  return startServer(handler);
}

/** Hardened app: headers, security.txt, no leaks, no exposure. */
export async function startKnownGood(): Promise<FixtureServer> {
  const handler: http.RequestListener = (req, res) => {
    const url = new URL(req.url || '/', 'http://fixture.local');
    const path = url.pathname;

    // Redirect params must NOT bounce off-domain
    const next = url.searchParams.get('next') || url.searchParams.get('redirect');
    if (next) {
      if (next.startsWith('/') && !next.startsWith('//')) {
        res.writeHead(302, { location: next });
      } else {
        res.writeHead(400, { 'content-type': 'text/plain' });
        res.end('invalid redirect');
      }
      return;
    }

    if (path === '/.well-known/security.txt') {
      send(
        res,
        200,
        'Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00.000Z\nPreferred-Languages: en\n',
        { 'content-type': 'text/plain' },
      );
      return;
    }

    if (path === '/robots.txt') {
      send(res, 200, 'User-agent: *\nAllow: /\n', { 'content-type': 'text/plain' });
      return;
    }

    if (path === '/sitemap.xml') {
      send(
        res,
        200,
        '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/</loc></url></urlset>',
        { 'content-type': 'application/xml' },
      );
      return;
    }

    // Sensitive paths → 404 (not SPA catch-all with HTML)
    if (
      path.startsWith('/.') ||
      path.includes('backup') ||
      path.includes('actuator') ||
      path.includes('swagger') ||
      path.includes('metrics') ||
      path.includes('debug') ||
      path.endsWith('.bak') ||
      path === '/package.json' ||
      path === '/wrangler.toml' ||
      path === '/config.json' ||
      path === '/docker-compose.yml' ||
      path === '/api-docs' ||
      path === '/server-status'
    ) {
      send(res, 404, 'Not Found', { 'content-type': 'text/plain' });
      return;
    }

    send(res, 200, CLEAN_HTML, HARDENED_HEADERS);
  };

  return startServer(handler);
}
