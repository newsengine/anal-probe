// src/detect.ts
// Black-box framework/platform fingerprinting from the already-fetched homepage (headers + cookies +
// HTML markers) — no extra requests. Feeds the `framework` category, which only runs a stack's targeted
// checks when that stack is detected with HIGH confidence, so we don't probe (or false-positive) for a
// framework that isn't there. Pure + testable: detectStacks() takes plain inputs.

export type StackName =
  | 'Next.js' | 'Nuxt' | 'WordPress' | 'Laravel' | 'Django' | 'Rails' | 'Spring Boot' | 'ASP.NET' | 'Express' | 'PHP';

export interface StackSignal { name: StackName; confidence: 'high' | 'medium' | 'low'; why: string[] }

export interface DetectInput { html: string; headers: Headers; setCookie: string[] }

interface Rule { name: StackName; signals: { weight: 2 | 1; why: string; test: (i: DetectInput, h: (n: string) => string) => boolean }[] }

const RULES: Rule[] = [
  { name: 'Next.js', signals: [
    { weight: 2, why: '__NEXT_DATA__ in HTML', test: (i) => /id="__NEXT_DATA__"|__NEXT_DATA__\s*=/.test(i.html) },
    { weight: 2, why: 'x-powered-by: Next.js', test: (_i, h) => /next\.js/i.test(h('x-powered-by')) },
    { weight: 1, why: '/_next/ asset references', test: (i) => /\/_next\//.test(i.html) },
    { weight: 1, why: 'next-auth cookie', test: (i) => i.setCookie.some((c) => /next-auth|authjs/i.test(c)) },
  ] },
  { name: 'Nuxt', signals: [
    { weight: 2, why: '__NUXT__ in HTML', test: (i) => /window\.__NUXT__|id="__nuxt"/.test(i.html) },
    { weight: 1, why: '/_nuxt/ asset references', test: (i) => /\/_nuxt\//.test(i.html) },
  ] },
  { name: 'WordPress', signals: [
    { weight: 2, why: 'generator meta = WordPress', test: (i) => /<meta[^>]+name=["']generator["'][^>]+WordPress/i.test(i.html) },
    { weight: 2, why: '/wp-content or /wp-includes references', test: (i) => /\/wp-(content|includes)\//.test(i.html) },
    { weight: 1, why: 'wp-json link', test: (i, h) => /wp-json/.test(i.html) || /wp-json/.test(h('link')) },
  ] },
  { name: 'Laravel', signals: [
    { weight: 2, why: 'laravel_session cookie', test: (i) => i.setCookie.some((c) => /^laravel_session=/i.test(c)) },
    { weight: 1, why: 'XSRF-TOKEN cookie', test: (i) => i.setCookie.some((c) => /^XSRF-TOKEN=/i.test(c)) },
  ] },
  { name: 'Django', signals: [
    { weight: 2, why: 'csrftoken + sessionid cookies', test: (i) => i.setCookie.some((c) => /^csrftoken=/i.test(c)) && i.setCookie.some((c) => /^sessionid=/i.test(c)) },
    { weight: 1, why: 'csrftoken cookie', test: (i) => i.setCookie.some((c) => /^csrftoken=/i.test(c)) },
  ] },
  { name: 'Rails', signals: [
    { weight: 2, why: 'x-runtime header + _session cookie', test: (i, h) => !!h('x-runtime') && i.setCookie.some((c) => /_session=/i.test(c)) },
    { weight: 1, why: 'csrf-param authenticity_token', test: (i) => /name=["']csrf-param["'][^>]+content=["']authenticity_token/i.test(i.html) },
  ] },
  { name: 'Spring Boot', signals: [
    { weight: 2, why: 'X-Application-Context header', test: (_i, h) => !!h('x-application-context') },
    { weight: 1, why: 'JSESSIONID cookie', test: (i) => i.setCookie.some((c) => /^JSESSIONID=/i.test(c)) },
  ] },
  { name: 'ASP.NET', signals: [
    { weight: 2, why: 'X-AspNet-Version header', test: (_i, h) => !!h('x-aspnet-version') },
    { weight: 2, why: 'x-powered-by: ASP.NET', test: (_i, h) => /asp\.net/i.test(h('x-powered-by')) },
    { weight: 1, why: 'ASP.NET_SessionId cookie', test: (i) => i.setCookie.some((c) => /^ASP\.NET_SessionId=/i.test(c)) },
  ] },
  { name: 'Express', signals: [
    { weight: 2, why: 'x-powered-by: Express', test: (_i, h) => /express/i.test(h('x-powered-by')) },
  ] },
  { name: 'PHP', signals: [
    { weight: 1, why: 'x-powered-by: PHP', test: (_i, h) => /php/i.test(h('x-powered-by')) },
    { weight: 1, why: 'PHPSESSID cookie', test: (i) => i.setCookie.some((c) => /^PHPSESSID=/i.test(c)) },
  ] },
];

/** Fingerprint the stack(s). Confidence: high = a weight-2 signal or ≥2 signals; medium = one weight-1; else low. */
export function detectStacks(inp: DetectInput): StackSignal[] {
  const h = (n: string) => inp.headers.get(n) || '';
  const out: StackSignal[] = [];
  for (const rule of RULES) {
    const hit = rule.signals.filter((s) => { try { return s.test(inp, h); } catch { return false; } });
    if (!hit.length) continue;
    const score = hit.reduce((n, s) => n + s.weight, 0);
    const confidence = score >= 2 ? 'high' : hit.length >= 1 ? 'medium' : 'low';
    out.push({ name: rule.name, confidence: hit.length >= 2 ? 'high' : confidence, why: hit.map((s) => s.why) });
  }
  // Express/PHP are often implied by a more specific stack (Laravel⇒PHP) — keep them but they rank lower.
  return out.sort((a, b) => ({ high: 0, medium: 1, low: 2 }[a.confidence] - { high: 0, medium: 1, low: 2 }[b.confidence]));
}
