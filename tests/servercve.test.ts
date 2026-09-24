/**
 * #36 — server-banner CVE correlation. Proves a disclosed vulnerable version is flagged with its CVE,
 * and that patched / non-matching versions are not (low false-positive).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serverCveFindings, parseServerBanners } from '../dist/servercve.js';
import type { ScanContext } from '../dist/types.js';

const ctxWith = (headers: Record<string, string>): ScanContext =>
  ({ headers: new Headers(headers), origin: 'https://x.test', baseUrl: 'https://x.test', url: new URL('https://x.test'), html: '', opts: {} } as ScanContext);

test('servercve: parseServerBanners pulls product/version pairs', () => {
  const b = parseServerBanners(ctxWith({ server: 'Apache/2.4.49 (Ubuntu)', 'x-powered-by': 'PHP/7.3.1' }));
  assert.deepEqual(b.map((x) => `${x.product}/${x.version}`).sort(), ['Apache/2.4.49', 'PHP/7.3.1']);
});

test('servercve: vulnerable Apache 2.4.49 is flagged with its CVE', () => {
  const f = serverCveFindings(ctxWith({ server: 'Apache/2.4.49 (Ubuntu)' }));
  assert.ok(f.some((x) => x.id === 'components.server-cve.CVE-2021-41773' && !x.pass), `expected CVE-2021-41773, got ${f.map((x) => x.id).join(',')}`);
});

test('servercve: OpenSSH 9.6 regreSSHion + PHP-FPM RCE are flagged', () => {
  assert.ok(serverCveFindings(ctxWith({ server: 'OpenSSH/9.6' })).some((x) => x.id.endsWith('CVE-2024-6387')));
  assert.ok(serverCveFindings(ctxWith({ 'x-powered-by': 'PHP/7.3.1' })).some((x) => x.id.endsWith('CVE-2019-11043')));
});

test('servercve: patched / non-matching versions do not false-positive', () => {
  assert.equal(serverCveFindings(ctxWith({ server: 'Apache/2.4.58' })).length, 0);
  assert.equal(serverCveFindings(ctxWith({ server: 'nginx/1.18.0' })).length, 0);
  assert.equal(serverCveFindings(ctxWith({ server: 'OpenSSH/9.8' })).length, 0);
  assert.equal(serverCveFindings(ctxWith({})).length, 0);
});
