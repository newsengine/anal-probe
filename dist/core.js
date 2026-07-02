// src/core.ts
// Zero-dependency HTTP + HTML + secret-scanning helpers. Kept regex-based on purpose: the whole kit
// must run via `npx` with no install and no headless browser, so a vibe coder can point it at a
// deploy in one command. Regex HTML parsing is "good enough" for black-box posture checks.
import tls from 'node:tls';
/**
 * Days until the served TLS certificate expires (null if it can't be determined). Uses a raw TLS
 * connection because fetch() doesn't expose the peer certificate.
 */
export function tlsCertDaysRemaining(host, port = 443) {
    return new Promise((resolve) => {
        let done = false;
        const finish = (v) => { if (!done) {
            done = true;
            resolve(v);
        } };
        try {
            const socket = tls.connect({ host, port, servername: host, timeout: 8000 }, () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                if (!cert || !cert.valid_to)
                    return finish(null);
                finish(Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000));
            });
            socket.on('error', () => finish(null));
            socket.on('timeout', () => { socket.destroy(); finish(null); });
        }
        catch {
            finish(null);
        }
    });
}
// Every network call gets a hard deadline so a dead/slow/hostile site can't hang the scan forever.
export const DEFAULT_TIMEOUT_MS = 10_000;
/** fetch() with an AbortController timeout. Merges any caller-supplied signal-less init. */
async function fetchWithTimeout(url, init, timeoutMs) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
        return await fetch(url, { signal: ac.signal, ...init });
    }
    finally {
        clearTimeout(timer);
    }
}
export async function safeFetch(url, init, timeoutMs = DEFAULT_TIMEOUT_MS) {
    try {
        return await fetchWithTimeout(url, { redirect: 'manual', ...init }, timeoutMs);
    }
    catch {
        return null;
    }
}
/**
 * Fetch text with a hard timeout AND a streaming byte cap: we stop reading once maxBytes have arrived,
 * so a gzip bomb / endless stream can't OOM the process (arrayBuffer() would buffer the whole body first).
 * Returns '' on any failure. Binary responses are decoded lossily — callers only regex over them.
 */
export async function fetchText(url, init, maxBytes = 3_000_000, timeoutMs = DEFAULT_TIMEOUT_MS) {
    try {
        const res = await fetchWithTimeout(url, { redirect: 'follow', ...init }, timeoutMs);
        if (!res.ok || !res.body)
            return '';
        const reader = res.body.getReader();
        const decoder = new TextDecoder('utf-8', { fatal: false });
        let out = '';
        let read = 0;
        for (;;) {
            const { done, value } = await reader.read();
            if (done)
                break;
            read += value.byteLength;
            out += decoder.decode(value, { stream: true });
            if (read >= maxBytes) {
                await reader.cancel();
                break;
            }
        }
        out += decoder.decode();
        return out.length > maxBytes ? out.slice(0, maxBytes) : out;
    }
    catch {
        return '';
    }
}
export function headerGet(h, name) {
    if (h instanceof Headers)
        return h.get(name);
    return h[name] ?? h[name.toLowerCase()] ?? null;
}
/** Resolve a possibly-relative href against the page origin; null if it can't be parsed. */
export function resolveUrl(base, href) {
    try {
        return new URL(href, base).toString();
    }
    catch {
        return null;
    }
}
export function sameOrigin(a, b) {
    try {
        return new URL(a).origin === new URL(b).origin;
    }
    catch {
        return false;
    }
}
// ---- tiny HTML extractors (regex, case-insensitive) ----
export function matchAllGroups(html, re) {
    const out = [];
    for (const m of html.matchAll(re))
        if (m[1] != null)
            out.push(m[1]);
    return out;
}
export const html = {
    title: (h) => (h.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? '').trim(),
    hasLang: (h) => /<html[^>]*\blang\s*=\s*["']?[a-z]/i.test(h),
    metaContent: (h, name) => {
        // matches <meta name="x" content="y"> or property="x" in either attribute order
        const re = new RegExp(`<meta[^>]+(?:name|property)\\s*=\\s*["']${name.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}["'][^>]*>`, 'i');
        const tag = h.match(re)?.[0];
        if (!tag)
            return null;
        return tag.match(/content\s*=\s*["']([^"']*)["']/i)?.[1] ?? '';
    },
    hasViewport: (h) => /<meta[^>]+name\s*=\s*["']viewport["']/i.test(h),
    canonical: (h) => h.match(/<link[^>]+rel\s*=\s*["']canonical["'][^>]*>/i)?.[0]?.match(/href\s*=\s*["']([^"']+)["']/i)?.[1] ?? null,
    scripts: (h) => matchAllGroups(h, /<script[^>]+src\s*=\s*["']([^"']+)["']/gi),
    links: (h) => matchAllGroups(h, /<a\s[^>]*href\s*=\s*["']([^"'#]+)["']/gi),
    images: (h) => {
        const out = [];
        for (const m of h.matchAll(/<img\s[^>]*>/gi)) {
            const tag = m[0];
            const src = tag.match(/\bsrc\s*=\s*["']([^"']+)["']/i)?.[1];
            if (src)
                out.push({ src, hasAlt: /\balt\s*=/i.test(tag) });
        }
        return out;
    },
    h1Count: (h) => (h.match(/<h1[\s>]/gi) || []).length,
    // Inputs that should be labelled (excludes hidden/submit/button) vs total <label> count.
    inputsNeedingLabel: (h) => (h.match(/<input\b(?![^>]*\btype\s*=\s*["'](?:hidden|submit|button|image|reset)["'])[^>]*>/gi) || []).length,
    labelCount: (h) => (h.match(/<label[\s>]/gi) || []).length,
    // http:// resources referenced from the page (mixed content when the page is https).
    insecureRefs: (h) => matchAllGroups(h, /(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi).filter((u) => !/^http:\/\/(localhost|127\.)/i.test(u)),
};
// High-confidence, low-false-positive patterns. Anything that's *meant* to be public (e.g. Stripe
// pk_live, Supabase anon key) is intentionally NOT here — only things that should never reach a browser.
export const SECRET_RULES = [
    { id: 'aws.akid', name: 'AWS access key id', severity: 'high', re: /\bAKIA[0-9A-Z]{16}\b/ },
    { id: 'stripe.sk_live', name: 'Stripe live secret key', severity: 'high', re: /\bsk_live_[0-9a-zA-Z]{20,}\b/ },
    { id: 'stripe.rk_live', name: 'Stripe live restricted key', severity: 'high', re: /\brk_live_[0-9a-zA-Z]{20,}\b/ },
    { id: 'privatekey', name: 'Private key block', severity: 'high', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
    { id: 'github.pat', name: 'GitHub personal access token', severity: 'high', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/ },
    { id: 'github.pat_fine', name: 'GitHub fine-grained token', severity: 'high', re: /\bgithub_pat_[0-9A-Za-z_]{60,}\b/ },
    { id: 'slack.token', name: 'Slack token', severity: 'high', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
    { id: 'anthropic.key', name: 'Anthropic API key', severity: 'high', re: /\bsk-ant-[0-9A-Za-z_-]{20,}\b/ },
    { id: 'openai.key', name: 'OpenAI API key', severity: 'high', re: /\bsk-(?:proj-)?[0-9A-Za-z]{20}[0-9A-Za-z_-]{10,}\b/ },
    { id: 'google.apikey', name: 'Google API key', severity: 'medium', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
    { id: 'sendgrid.key', name: 'SendGrid API key', severity: 'high', re: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/ },
    { id: 'twilio.sk', name: 'Twilio API key', severity: 'high', re: /\bSK[0-9a-fA-F]{32}\b/ },
    {
        // A JWT whose payload decodes to role=service_role (Supabase) — full DB bypass if shipped to the client.
        id: 'supabase.service_role',
        name: 'Supabase service_role key',
        severity: 'high',
        re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
        confirm: (m) => {
            try {
                const payload = JSON.parse(Buffer.from(m.split('.')[1], 'base64').toString('utf8'));
                return payload?.role === 'service_role';
            }
            catch {
                return false;
            }
        },
    },
];
export function scanSecrets(blob) {
    const hits = [];
    const seen = new Set();
    for (const rule of SECRET_RULES) {
        for (const m of blob.matchAll(new RegExp(rule.re, rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g'))) {
            const match = m[0];
            if (rule.confirm && !rule.confirm(match, blob))
                continue;
            const key = `${rule.id}:${match.slice(0, 12)}`;
            if (seen.has(key))
                continue;
            seen.add(key);
            // Redact: keep enough to identify, hide the secret body.
            const sample = match.length > 14 ? `${match.slice(0, 8)}…${match.slice(-4)}` : match;
            hits.push({ ruleId: rule.id, name: rule.name, severity: rule.severity, sample });
        }
    }
    return hits;
}
