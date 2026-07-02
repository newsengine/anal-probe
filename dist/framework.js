// src/framework.ts
// Stack-specific check groups. We only probe a framework's known-misconfig surfaces when detect.ts
// fingerprinted that stack with HIGH confidence — so we neither waste requests nor false-positive on a
// stack that isn't present. Every probe is a safe GET (no attack payloads), body-validated.
import { safeFetch } from './core.js';
import { detectStacks } from './detect.js';
import { findSensitiveFields } from './testkit.js';
const f = (id, title, severity, pass, detail, fix) => ({ category: 'framework', id, title, severity, pass, detail, fix });
async function probePaths(ctx, probes) {
    const out = [];
    for (const p of probes) {
        const res = await safeFetch(ctx.origin + p.path, { redirect: 'follow', headers: ctx.opts.extraHeaders });
        if (!res || !res.ok)
            continue;
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        const body = (await res.text()).slice(0, 6000);
        if (p.looksReal(body, ct)) {
            out.push(f(`framework${p.path}`, `${p.label} is publicly reachable`, p.severity, false, `GET ${p.path} → 200 and the body looks like a real ${p.label}`, p.fix));
        }
    }
    return out;
}
const CHECKS = {
    'Next.js': async (ctx) => {
        const out = [];
        // Secrets accidentally serialized into the page's __NEXT_DATA__ (server config leaking to the client).
        const blob = ctx.html.match(/id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/i)?.[1] || '';
        const leaked = blob ? findSensitiveFields(blob) : [];
        out.push(f('framework.next.data-secrets', leaked.length ? 'Secrets in __NEXT_DATA__' : '__NEXT_DATA__ has no secret fields', leaked.length ? 'high' : 'info', leaked.length === 0, leaked.length ? `__NEXT_DATA__ contains ${leaked.join(', ')}` : 'no sensitive fields serialized into the page', leaked.length ? 'Never put secrets in getServerSideProps/getStaticProps return values — they ship to the browser in __NEXT_DATA__. Use server-only env + API routes.' : undefined));
        return out;
    },
    WordPress: async (ctx) => {
        const out = [];
        // User enumeration via the REST API — leaks usernames/slugs for credential stuffing.
        const users = await safeFetch(ctx.origin + '/wp-json/wp/v2/users', { redirect: 'follow' });
        if (users && users.ok) {
            const body = await users.text();
            if (/"slug"\s*:/.test(body) && /\[/.test(body.trim()[0] || '')) {
                out.push(f('framework.wp.user-enum', 'WordPress REST API exposes user list', 'medium', false, '/wp-json/wp/v2/users returns usernames/slugs', 'Restrict /wp-json/wp/v2/users to authenticated requests (a security plugin or filter) to stop username harvesting.'));
            }
        }
        out.push(...await probePaths(ctx, [
            { path: '/xmlrpc.php', severity: 'low', label: 'XML-RPC endpoint', looksReal: (b) => /XML-RPC server accepts POST requests only|methodResponse|xmlrpc/i.test(b), fix: 'Disable xmlrpc.php if unused — it enables brute-force amplification and pingback DDoS.' },
            { path: '/wp-config.php.bak', severity: 'high', label: 'wp-config backup', looksReal: (b) => /DB_PASSWORD|DB_NAME|AUTH_KEY/.test(b), fix: 'Delete wp-config.php.bak from the webroot — it exposes your DB credentials and salts.' },
        ]));
        return out;
    },
    Laravel: async (ctx) => probePaths(ctx, [
        { path: '/telescope/requests', severity: 'high', label: 'Laravel Telescope', looksReal: (b) => /Telescope|telescope/.test(b) && !/<title>Not Found/i.test(b), fix: 'Restrict Telescope to local/authorized users (TelescopeServiceProvider gate) — it exposes requests, queries, and payloads.' },
        { path: '/_ignition/health-check', severity: 'high', label: 'Ignition debug endpoint', looksReal: (b, ct) => ct.includes('json') && /"can_execute_commands"|"result"\s*:\s*"ok"/.test(b), fix: 'Set APP_DEBUG=false in production and update laravel/ignition — /_ignition has a known RCE (CVE-2021-3129).' },
    ]),
    Rails: async (ctx) => probePaths(ctx, [
        { path: '/rails/info/properties', severity: 'high', label: 'Rails info/properties', looksReal: (b) => /Ruby version|Rails version|Middleware/i.test(b), fix: 'Rails dev routes are exposed — ensure config.consider_all_requests_local=false and the app runs in production mode.' },
        { path: '/sidekiq', severity: 'medium', label: 'Sidekiq dashboard', looksReal: (b) => /Sidekiq/i.test(b) && /Processed|Enqueued|Busy/i.test(b), fix: 'Protect the /sidekiq dashboard behind auth (constraints/ Devise) — it exposes job data and lets anyone retry/kill jobs.' },
    ]),
    Django: async (ctx) => {
        // DEBUG=True renders a detailed error page on an unknown route (leaks settings, paths, SQL).
        const res = await safeFetch(ctx.origin + '/__anal_probe_django_debug__', { redirect: 'follow' });
        const out = [];
        if (res) {
            const body = (await res.text()).slice(0, 8000);
            // Canonical Django debug-500 phrase only — appears nowhere but the DEBUG=True error page (avoids
            // matching docs that merely mention "Django Version:" or the settings-module env var name).
            const debug = /You're seeing this error because you have\s*(?:<code>)?\s*DEBUG\s*=\s*True/i.test(body)
                || (/DJANGO_SETTINGS_MODULE/.test(body) && /Traceback \(most recent call last\)|<div id="?traceback/i.test(body));
            out.push(f('framework.django.debug', debug ? 'Django DEBUG=True in production' : 'Django DEBUG not exposed', debug ? 'high' : 'info', !debug, debug ? 'an unknown URL returned a Django debug error page (leaks settings, paths, SQL)' : 'no Django debug page on an unknown route', debug ? 'Set DEBUG=False in production settings — the debug page leaks your settings, installed apps, and stack traces.' : undefined));
        }
        return out;
    },
    'Spring Boot': async (ctx) => probePaths(ctx, [
        { path: '/actuator/env', severity: 'high', label: 'Spring actuator /env', looksReal: (b, ct) => ct.includes('json') && /"propertySources"|"activeProfiles"/.test(b), fix: 'Restrict actuator endpoints (management.endpoints.web.exposure) — /env leaks config, and /heapdump leaks memory (incl. secrets).' },
        { path: '/actuator/heapdump', severity: 'high', label: 'Spring actuator /heapdump', looksReal: (b) => b.startsWith('JAVA PROFILE') || /HPROF/.test(b.slice(0, 20)), fix: 'Disable /actuator/heapdump publicly — a heap dump contains live memory including credentials and tokens.' },
        { path: '/actuator/mappings', severity: 'low', label: 'Spring actuator /mappings', looksReal: (b, ct) => ct.includes('json') && /"dispatcherServlets"|"handler"/.test(b), fix: 'Restrict actuator exposure — /mappings hands attackers your full route map.' },
    ]),
    'ASP.NET': async (ctx) => probePaths(ctx, [
        { path: '/elmah.axd', severity: 'high', label: 'ELMAH error log', looksReal: (b) => /Error Log for|ELMAH/i.test(b), fix: 'Lock down elmah.axd (allowRemoteAccess=false / auth) — it exposes application error logs with stack traces and data.' },
        { path: '/trace.axd', severity: 'medium', label: 'ASP.NET trace viewer', looksReal: (b) => /Application Trace|trace\.axd/i.test(b), fix: 'Disable tracing in production (<trace enabled="false"/>) — trace.axd leaks requests, cookies, and server variables.' },
    ]),
};
export async function frameworkChecks(ctx) {
    if (!ctx.res)
        return [];
    const stacks = ctx.stacks ?? detectStacks({ html: ctx.html, headers: ctx.headers, setCookie: ctx.headers.getSetCookie?.() ?? [] });
    const high = stacks.filter((s) => s.confidence === 'high');
    if (!high.length) {
        return [f('framework.none', 'No framework confidently fingerprinted', 'info', true, stacks.length ? `low-confidence guesses: ${stacks.map((s) => s.name).join(', ')}` : 'no distinctive stack markers found')];
    }
    const out = [f('framework.detected', `Detected: ${high.map((s) => s.name).join(', ')}`, 'info', true, high.map((s) => `${s.name} (${s.why.join('; ')})`).join(' | '))];
    for (const s of high) {
        const runner = CHECKS[s.name];
        if (runner)
            out.push(...await runner(ctx).catch(() => []));
    }
    return out;
}
