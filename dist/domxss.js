// src/domxss.ts
// DOM-based XSS heuristic. Flags a user-controllable SOURCE (URL/hash/referrer/window.name) flowing
// DIRECTLY into a dangerous HTML/JS SINK (innerHTML, document.write, eval, insertAdjacentHTML) inside the
// page's INLINE scripts. Kept HIGH-CONFIDENCE on purpose: it only fires when a taint source appears inside
// the same sink expression (e.g. `el.innerHTML = location.hash`) — not on a lone sink — so it doesn't
// drown the report in "you used innerHTML" noise. Static analysis only; nothing is executed.
//
// Caveat: scans inline <script> blocks (bundled app code isn't inspected here), so a clean result is not a
// guarantee — it's a cheap catch for the classic inline footguns. Findings still warrant manual review.
const f = (id, title, severity, pass, detail, fix) => ({ category: 'security', id, title, severity, pass, detail, fix });
// A "source" is anything an attacker can influence via the URL/navigation.
const SOURCE = String.raw `(?:location\s*\.\s*(?:hash|search|href|pathname)|location(?=\s*[)\];,])|document\s*\.\s*(?:URL|documentURI|referrer|baseURI)|window\s*\.\s*name)`;
// Each rule: a sink expression that contains a source within the same statement/call.
const RULES = [
    { sink: 'innerHTML/outerHTML', re: new RegExp(String.raw `\.\s*(?:inner|outer)HTML\s*\+?=\s*[^;\n]{0,120}?` + SOURCE, 'i') },
    { sink: 'document.write', re: new RegExp(String.raw `document\s*\.\s*write(?:ln)?\s*\([^)]{0,160}?` + SOURCE, 'i') },
    { sink: 'insertAdjacentHTML', re: new RegExp(String.raw `insertAdjacentHTML\s*\([^)]{0,180}?` + SOURCE, 'i') },
    { sink: 'eval/new Function', re: new RegExp(String.raw `(?:^|[^.\w])(?:eval|Function)\s*\([^)]{0,160}?` + SOURCE, 'i') },
    { sink: 'jQuery .html()', re: new RegExp(String.raw `\.\s*html\s*\([^)]{0,120}?` + SOURCE, 'i') },
];
// Pure + testable: scan a blob of JS for direct source→sink flows.
export function scanDomXssSinks(js) {
    const hits = [];
    for (const r of RULES) {
        const m = js.match(r.re);
        if (m)
            hits.push({ sink: r.sink, snippet: m[0].replace(/\s+/g, ' ').trim().slice(0, 100) });
    }
    return hits;
}
export function domXssFindings(ctx) {
    if (!ctx.html)
        return [];
    const inlineScripts = [...ctx.html.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]).join('\n');
    const hits = scanDomXssSinks(inlineScripts);
    if (!hits.length)
        return []; // stay silent unless a direct flow is found (low-FP)
    const uniq = [...new Map(hits.map((h) => [h.sink, h])).values()];
    return [f('dom-xss', `Potential DOM XSS: user input reaches ${uniq.length} sink(s)`, 'medium', false, uniq.map((h) => `${h.sink} ← "${h.snippet}"`).join(' | ') + ' — a URL/referrer/window.name value flows into an HTML/JS sink in inline script', 'Never write untrusted URL data into innerHTML/document.write/eval. Use textContent, or sanitize with a library like DOMPurify before inserting HTML.')];
}
