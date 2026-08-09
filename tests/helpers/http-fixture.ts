/**
 * Shared local HTTP fixture helpers for probe self-tests.
 * Always bind 127.0.0.1 so CI never opens a public port.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';

export type FixtureServer = {
  url: string;
  port: number;
  close: () => Promise<void>;
};

export function startServer(
  handler: http.RequestListener,
): Promise<FixtureServer> {
  return new Promise((resolve, reject) => {
    const s = http.createServer(handler);
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        port: addr.port,
        close: () =>
          new Promise((res, rej) => {
            s.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}

export function send(
  res: http.ServerResponse,
  status: number,
  body: string | Buffer,
  headers: Record<string, string | string[]> = {},
): void {
  const h: Record<string, string | string[] | number> = {
    'content-length': Buffer.byteLength(body),
    ...headers,
  };
  res.writeHead(status, h);
  res.end(body);
}

/** Real-looking exposure bodies (must pass body validators in exposureChecks). */
export const EXPOSURE_BODIES: Record<string, { body: string | Buffer; type: string }> = {
  '/.env': {
    type: 'text/plain',
    body: 'DATABASE_URL=postgres://u:p@localhost/db\nSECRET_KEY=supersecret123\nAPI_TOKEN=tok_abc\n',
  },
  '/.env.local': {
    type: 'text/plain',
    body: 'NEXT_PUBLIC_X=1\nSTRIPE_SECRET_KEY=sk_test_placeholder_not_live_xxx\n',
  },
  '/.env.production': {
    type: 'text/plain',
    body: 'NODE_ENV=production\nSESSION_SECRET=prodsecretvalue\n',
  },
  '/.env.bak': {
    type: 'text/plain',
    body: 'OLD_SECRET=backup\nDATABASE_URL=postgres://old\n',
  },
  '/.git/config': {
    type: 'text/plain',
    body: '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/example/repo.git\n',
  },
  '/.git/HEAD': {
    type: 'text/plain',
    body: 'ref: refs/heads/main\n',
  },
  '/wrangler.toml': {
    type: 'text/plain',
    body: 'name = "leaky-app"\ncompatibility_date = "2024-01-01"\n',
  },
  '/package.json': {
    type: 'application/json',
    body: '{"name":"leaky-app","dependencies":{"express":"4.18.0"}}\n',
  },
  '/.npmrc': {
    type: 'text/plain',
    body: '//registry.npmjs.org/:_authToken=npm_leak_token_example\nregistry=https://registry.npmjs.org/\n',
  },
  '/docker-compose.yml': {
    type: 'text/yaml',
    body: 'services:\n  web:\n    image: node:20\n    ports:\n      - "3000:3000"\n',
  },
  '/backup.sql': {
    type: 'application/sql',
    body: 'CREATE TABLE users (id int, email text);\nINSERT INTO users VALUES (1, \'a@b.com\');\n',
  },
  '/.aws/credentials': {
    type: 'text/plain',
    body: '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n',
  },
  '/config.json': {
    type: 'application/json',
    body: '{"apiKey":"secret-key-value","database":"postgres://localhost/app"}\n',
  },
  '/actuator/health': {
    type: 'application/json',
    body: '{"status":"UP"}\n',
  },
  '/debug/vars': {
    type: 'application/json',
    body: '{"cmdline":["app"],"memstats":{"Alloc":1}}\n',
  },
  '/metrics': {
    type: 'text/plain',
    body: '# HELP http_requests_total Total HTTP requests\n# TYPE http_requests_total counter\nhttp_requests_total 42\n',
  },
  '/swagger.json': {
    type: 'application/json',
    body: '{"openapi":"3.0.0","info":{"title":"API","version":"1.0.0"},"paths":{}}\n',
  },
  '/api-docs': {
    type: 'text/html',
    body: '<html><body><div id="swagger-ui"></div><script src="/swagger-ui.js"></script></body></html>',
  },
  '/server-status': {
    type: 'text/html',
    body: '<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for localhost</h1></body></html>',
  },
  '/config.php.bak': {
    type: 'application/x-httpd-php',
    body: '<?php $db_password = "secret";\n',
  },
  '/index.php.bak': {
    type: 'application/x-httpd-php',
    body: '<?php echo "hello";\n',
  },
  '/web.config.bak': {
    type: 'application/xml',
    body: '<?xml version="1.0"?><configuration><connectionStrings><add name="db" connectionString="Server=.;"/></connectionStrings></configuration>',
  },
  '/backup.zip': {
    type: 'application/zip',
    body: Buffer.from('PK\x03\x04fakezipcontent'),
  },
  '/.git.zip': {
    type: 'application/zip',
    body: Buffer.from('PK\x03\x04fakegitzip'),
  },
  '/backup.tar.gz': {
    type: 'application/gzip',
    body: Buffer.from('\x1f\x8b\x08\x00fake gzip'),
  },
  '/backup.sql.gz': {
    type: 'application/gzip',
    body: Buffer.from('\x1f\x8b\x08\x00fake sql gzip'),
  },
};

/** Stripe-shaped live secret (must match SECRET_RULES length). Built without a literal sk_live_ prefix for push protection. */
export const FAKE_STRIPE_LIVE = ['sk', 'live', '51' + 'x'.repeat(28)].join('_');

export const FAKE_AWS_AKIA = 'AKIAIOSFODNN7EXAMPLE';

export const HARDENED_HEADERS: Record<string, string> = {
  'content-type': 'text/html; charset=utf-8',
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-frame-options': 'DENY',
  'content-security-policy':
    "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'cache-control': 'no-store',
};

export const CLEAN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <meta name="description" content="Hardened fixture app for vibetesting-agent true-negative tests."/>
  <meta property="og:title" content="Hardened fixture"/>
  <link rel="canonical" href="/"/>
  <title>Hardened fixture</title>
</head>
<body>
  <h1>Hardened fixture</h1>
  <p>No secrets. No exposed config. Security headers present.</p>
  <form method="post" action="/login">
    <label for="email">Email</label>
    <input id="email" name="email" type="email"/>
    <input type="hidden" name="csrf_token" value="fixture-csrf-token"/>
    <button type="submit">Go</button>
  </form>
</body>
</html>`;

export const LEAKY_HTML = `<!DOCTYPE html>
<html>
<head><title></title></head>
<body>
  <h1>Leaky fixture</h1>
  <h2>extra h1 competitor</h2>
  <img src="/broken-image.png"/>
  <a href="/broken-link">missing page</a>
  <script>
    // Deliberate client leak for secrets true-positive
    window.STRIPE_KEY = "${FAKE_STRIPE_LIVE}";
    window.AWS_KEY = "${FAKE_AWS_AKIA}";
  </script>
  <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
  <script src="https://cdn.example.com/lib.js"></script>
  <form method="post" action="/transfer">
    <input name="amount" value="100"/>
    <button type="submit">Send</button>
  </form>
  <script>
    // High-confidence DOM XSS pattern: location -> innerHTML
    document.body.innerHTML = location.hash;
  </script>
</body>
</html>`;
