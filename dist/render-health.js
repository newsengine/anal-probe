// src/render-health.ts
// Detects client-side render failures that a fetch scan — and even a `pageerror` listener — miss:
//   1. Error boundaries. A React/Vue error boundary CATCHES the thrown error and renders a fallback
//      ("Something went wrong"), so NO `pageerror` event fires and the document still returns 200. The
//      page looks healthy to every network-level check; the only signal is the rendered fallback text.
//      This is the exact class of bug that shipped as a blank "Something went wrong" screen (Sparkle #119).
//   2. Framework crash overlays (Next.js "Unhandled Runtime Error", Vite overlay, webpack overlay).
//   3. Blank app root — a known SPA mount point (#root / #__next / #app) that renders no meaningful
//      content after the network settles: the white-screen-of-death symptom.
//
// Used by both `browse` and `crawl`. The probe runs inside the page; the classifier turns its result
// into findings. Signatures are curated to real framework fallbacks and gated on "the fallback IS the
// page" (short visible text) to keep false positives near zero — a blog post that merely contains the
// words "something went wrong" in a paragraph won't trip it.
// Serialized to a string and injected via page.evaluate. Returns raw signals; classification is done
// host-side so the thresholds live in one place and are testable.
export const RENDER_HEALTH_PROBE = `() => {
  const bodyText = (document.body ? document.body.innerText || '' : '').trim();
  // Curated crash/fallback signatures — framework error boundaries & dev overlays.
  const SIGNATURES = [
    'something went wrong',
    'a fix is on the way',
    "we've been notified",
    'application error: a client-side exception',
    'unhandled runtime error',
    'this page could not be displayed',
    'oops, something',
    'an unexpected error has occurred',
    'client-side exception has occurred',
  ];
  // React minified invariant + chunk-load failures (dynamic import crashes).
  const REGEXES = [/minified react error #\\d+/i, /chunkloaderror/i, /loading chunk \\d+ failed/i];
  const lower = bodyText.toLowerCase();
  let errorSignature = null;
  for (const s of SIGNATURES) { if (lower.includes(s)) { errorSignature = s; break; } }
  if (!errorSignature) { for (const re of REGEXES) { const m = bodyText.match(re); if (m) { errorSignature = m[0]; break; } } }

  // Framework dev/prod error overlays rendered as dedicated elements.
  const OVERLAY_SEL = 'nextjs-portal, vite-error-overlay, #webpack-dev-server-client-overlay, [data-nextjs-dialog], #nextjs__container_errors_label';
  let overlay = null;
  try { const el = document.querySelector(OVERLAY_SEL); if (el) overlay = el.tagName.toLowerCase(); } catch (e) {}

  // Blank SPA root: a known mount exists but rendered nothing meaningful.
  const ROOTS = ['#root', '#__next', '#app', '[data-reactroot]', 'main'];
  let blankRoot = null, rootTextLen = -1;
  for (const sel of ROOTS) {
    let el; try { el = document.querySelector(sel); } catch (e) { el = null; }
    if (el) {
      const tl = (el.innerText || '').trim().length;
      const kids = el.querySelectorAll('input, textarea, select, img, svg, canvas, button, a, table').length;
      rootTextLen = tl;
      if (tl < 15 && kids === 0) blankRoot = sel;
      break; // first matching root wins
    }
  }
  return { visibleTextLen: bodyText.length, errorSignature, overlay, blankRoot, rootTextLen };
}`;
// Turn a probe result into findings. Always returns a healthy PASS finding when clean so the report
// records that the page was checked; callers that only surface failures can filter on `pass`.
export function renderHealthFindings(path, r, category = 'reliability') {
    const mk = (id, title, severity, pass, detail, fix) => ({ category, id: `${id}${path}`, title, severity, pass, detail, fix });
    // Error boundary: signature present AND the fallback dominates the page (short visible text). A long
    // page that merely mentions the phrase is not flagged.
    if (r.errorSignature && r.visibleTextLen > 0 && r.visibleTextLen < 600) {
        return [mk('render.errorboundary', `Client-side crash / error boundary rendered on ${path}`, 'high', false, `The page rendered a framework error fallback ("${r.errorSignature}") instead of content — an error boundary caught a thrown exception, so no uncaught error is reported but the page is broken for users.`, 'Find the component that throws on this route (often unguarded data — an undefined field/array). This class of bug returns HTTP 200 and produces no console pageerror, so only a rendered-state check catches it.')];
    }
    if (r.overlay) {
        return [mk('render.overlay', `Framework error overlay on ${path}`, 'high', false, `A framework error overlay (<${r.overlay}>) is present — an unhandled runtime error is being shown over the page.`, 'Fix the runtime error surfaced by the overlay; ship with error overlays disabled in production.')];
    }
    if (r.blankRoot) {
        return [mk('render.blank', `Blank app root on ${path}`, 'medium', false, `The SPA mount ${r.blankRoot} rendered no meaningful content (text length ${r.rootTextLen}, no elements) after the network settled — a white-screen render failure.`, 'The app mounted but produced no output — usually a crash during initial render or a failed critical data load. Check the console and the route component.')];
    }
    return [mk('render.ok', `Page renders content on ${path}`, 'info', true, `visible text ${r.visibleTextLen} chars, no error-boundary/overlay/blank-root`, undefined)];
}
