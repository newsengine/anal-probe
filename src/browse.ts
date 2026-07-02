// src/browse.ts
// OPT-IN browser-functional mode: the one part of anal-probe that drives a real (headless) browser, so
// it can catch aberrant behaviour a fetch-based scan can't — JavaScript errors, broken images that only
// fail after render, failed subresource loads, and forms that don't accept input. Kept OUT of the core
// zero-install scan: it needs `playwright-core` (an OPTIONAL dependency) and uses your installed Chrome.
//
//   npm i -D playwright-core
//   anal-probe browse <url> [--pages N] [--timeout ms] [--json] [--quiet]
//
// It's read-only: it navigates and types a throwaway string into inputs to confirm they accept input; it
// never submits forms or performs destructive actions.

import type { Finding, Severity } from './types.js';
import { discoverPages, normalizeUrl } from './probe.js';

const f = (id: string, title: string, severity: Severity, pass: boolean, detail: string, fix?: string): Finding =>
  ({ category: 'reliability', id, title, severity, pass, detail, fix });

/** Per-page functional check run inside the page context. Returns raw problem lists. */
const PAGE_PROBE = `() => {
  const out = { brokenImages: [], unlabeledInputs: 0, textInputs: 0, forms: document.forms.length, links: 0 };
  for (const img of document.images) {
    if (img.complete && img.naturalWidth === 0 && (img.getAttribute('src') || '').trim()) out.brokenImages.push(img.currentSrc || img.src);
  }
  const typeable = [...document.querySelectorAll('input, textarea')].filter((el) => {
    const t = (el.getAttribute('type') || 'text').toLowerCase();
    return !['hidden','submit','button','checkbox','radio','range','file','image','reset','color'].includes(t) && !el.disabled && !el.readOnly;
  });
  out.textInputs = typeable.length;
  out.links = document.querySelectorAll('a[href]').length;
  return out;
}`;

export async function browseChecks(startUrl: string, opts: { pages?: number; timeoutMs?: number; headers?: Record<string, string> } = {}): Promise<Finding[]> {
  let chromium: any;
  try { ({ chromium } = await import('playwright-core')); }
  catch { return [f('browse.missing-dep', 'browser mode needs playwright-core', 'info', true, 'run `npm i -D playwright-core` to enable `anal-probe browse` (uses your installed Chrome)')]; }

  const out: Finding[] = [];
  const timeoutMs = opts.timeoutMs ?? 20000;
  let browser: any;
  try {
    browser = await chromium.launch({ channel: 'chrome', headless: true });
  } catch {
    try { browser = await chromium.launch({ headless: true }); }
    catch { return [f('browse.no-browser', 'no browser available', 'info', true, 'install Chrome, or run `npx playwright install chromium`')]; }
  }
  const ctx = await browser.newContext({ extraHTTPHeaders: opts.headers });

  const start = normalizeUrl(startUrl);
  const pages = [start, ...(opts.pages && opts.pages > 1 ? await discoverPages(start, opts.pages - 1, { extraHeaders: opts.headers, timeoutMs }) : [])];

  for (const url of pages) {
    const page = await ctx.newPage();
    const jsErrors: string[] = [];
    const consoleErrors: string[] = [];
    const failedResponses: string[] = [];
    page.on('pageerror', (e: any) => jsErrors.push(String(e?.message || e)));
    page.on('console', (m: any) => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 160)); });
    page.on('response', (r: any) => { const s = r.status(); if (s >= 400 && r.request().resourceType() !== 'document') failedResponses.push(`${s} ${r.url().slice(0, 100)}`); });

    const path = (() => { try { return new URL(url).pathname || '/'; } catch { return url; } })();
    let probe: any = null;
    try {
      await page.goto(url, { waitUntil: 'networkidle', timeout: timeoutMs });
      await page.waitForTimeout(800);
      probe = await page.evaluate(`(${PAGE_PROBE})()`);
    } catch (e: any) {
      out.push(f(`browse.load${path}`, `Page failed to load: ${path}`, 'high', false, String(e?.message || e).slice(0, 160), 'The page errored or timed out in a real browser — check the route renders.'));
      await page.close();
      continue;
    }

    // Uncaught JS errors — the page's interactivity is likely broken.
    out.push(f(`browse.jserrors${path}`, jsErrors.length ? `${jsErrors.length} JavaScript error(s) on ${path}` : `No JS errors on ${path}`, jsErrors.length ? 'high' : 'info', jsErrors.length === 0, jsErrors.length ? jsErrors.slice(0, 3).join(' | ') : 'clean', jsErrors.length ? 'Uncaught exceptions break interactivity — fix the errors thrown on load.' : undefined));
    // Console errors — softer signal.
    if (consoleErrors.length) out.push(f(`browse.console${path}`, `${consoleErrors.length} console error(s) on ${path}`, 'low', false, consoleErrors.slice(0, 3).join(' | '), 'Investigate console errors — often failed fetches or missing assets.'));
    // Failed subresources (images/scripts/styles/XHR returning 4xx/5xx).
    if (failedResponses.length) out.push(f(`browse.failed-requests${path}`, `${failedResponses.length} failed request(s) on ${path}`, 'medium', false, failedResponses.slice(0, 5).join(', '), 'Fix or remove resources that 4xx/5xx — they break rendering and features.'));
    // Broken images (rendered, naturalWidth 0).
    if (probe.brokenImages.length) out.push(f(`browse.images${path}`, `${probe.brokenImages.length} broken image(s) on ${path}`, 'medium', false, probe.brokenImages.slice(0, 4).join(', '), 'Fix the image src / missing files — they show as broken in the browser.'));

    // Forms accept input: type a throwaway string into the first typeable input and read it back.
    if (probe.textInputs > 0) {
      let accepted = false;
      try {
        const first = page.locator('input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=checkbox]):not([type=radio]):not([type=file]):not([disabled]):not([readonly]), textarea').first();
        await first.fill('anal-probe-test', { timeout: 3000 });
        accepted = (await first.inputValue()) === 'anal-probe-test';
      } catch { accepted = false; }
      out.push(f(`browse.forminput${path}`, accepted ? `Form inputs accept input on ${path}` : `A form input did NOT accept input on ${path}`, accepted ? 'info' : 'medium', accepted, accepted ? `${probe.textInputs} typeable input(s), first accepts text` : 'typing into the first input did not update its value — it may be broken/covered/controlled', accepted ? undefined : 'A visible input that won\'t take typed text is broken — check overlays, disabled state, or a controlled-component bug.'));
    }

    await page.close();
  }

  await browser.close();
  return out;
}
