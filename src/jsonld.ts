// src/jsonld.ts
// JSON-LD script-breakout XSS check. `<script type="application/ld+json">` blocks are a classic
// stored-XSS footgun: emitters build them as `<script …>${JSON.stringify(data)}</script>`, but
// JSON.stringify does NOT neutralise the byte sequence `</script>`. So if any interpolated field
// (a title, a name, a description — often user- or crawler-supplied) contains `</script><script>…`,
// it closes the JSON-LD block early and the injected markup executes on the page's own origin.
//
// This is fully generalisable — any site that emits structured data is a candidate — and it's a
// deterministic, high-confidence static check (no payload injected, nothing executed):
//   • a JSON-LD block whose content doesn't parse as JSON  → it was already truncated at an injected
//     `</script>` (an ACTIVE breakout) — HIGH.
//   • a block that parses but whose raw text contains `</script`, `<script`, or `<!--`             → HIGH.
//   • a block that parses but contains any other tag-like `<` (i.e. the emitter isn't escaping `<`
//     as `<`) → the site is one `</script>`-bearing value away from XSS — MEDIUM (hardening).
//   • a block that parses and has no unescaped tag-like `<`                                        → safe.
//
// The correct fix is to escape the serialised JSON before embedding: replace `<` → `<` (and the
// line/paragraph separators U+2028/U+2029). This is the exact class of bug that ships when teams rely
// on JSON.stringify alone for schema.org / Open Graph structured data.

import type { Finding, ScanContext, Severity } from './types.js';

const f = (id: string, title: string, severity: Severity, pass: boolean, detail: string, fix?: string): Finding =>
  ({ category: 'security', id, title, severity, pass, detail, fix });

const FIX = 'When emitting <script type="application/ld+json">, escape the serialised JSON: replace < with \\u003c (and U+2028/U+2029). JSON.stringify alone does NOT neutralise </script>, so any interpolated field can break out and run script.';

// Sequences that actually terminate/escape "script data" per the HTML parser.
const BREAKOUT = /<\/script|<script|<!--/i;
// Any tag-like '<' → proof the emitter isn't escaping '<' as <.
const TAGLIKE = /<[/!a-z]/i;

export interface JsonLdIssue { index: number; severity: 'high' | 'medium'; detail: string }

/** Pure + testable: scan a blob of HTML for JSON-LD script-breakout risk. */
export function scanJsonLdBreakout(html: string): JsonLdIssue[] {
  const issues: JsonLdIssue[] = [];
  const re = /<script\b[^>]*\btype\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script\s*>/gi;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(html)) !== null) {
    i++;
    const raw = m[1];
    let parses = true;
    try { JSON.parse(raw.trim()); } catch { parses = false; }
    if (!parses) {
      issues.push({ index: i, severity: 'high', detail: `JSON-LD block #${i} does not parse as JSON — a value was almost certainly truncated at an injected </script>, i.e. an active script breakout (stored XSS).` });
      continue;
    }
    if (BREAKOUT.test(raw)) {
      issues.push({ index: i, severity: 'high', detail: `JSON-LD block #${i} contains a raw </script>/<script>/<!-- sequence in its data — a value breaks (or is about to break) out of the script element (stored XSS).` });
      continue;
    }
    if (TAGLIKE.test(raw)) {
      issues.push({ index: i, severity: 'medium', detail: `JSON-LD block #${i} contains an unescaped tag-like "<" — the emitter does not escape < as \\u003c, so any field value containing </script> will break out and execute (latent stored XSS).` });
    }
  }
  return issues;
}

export function jsonLdFindings(ctx: ScanContext): Finding[] {
  if (!ctx.html) return [];
  const hasJsonLd = /<script\b[^>]*\btype\s*=\s*["']application\/ld\+json/i.test(ctx.html);
  if (!hasJsonLd) return [];
  const issues = scanJsonLdBreakout(ctx.html);
  if (issues.length === 0) {
    return [f('xss.jsonld', 'JSON-LD is safely escaped', 'info', true, 'all application/ld+json blocks parse and escape < as \\u003c')];
  }
  return issues.map((it) =>
    f(
      it.index === 1 ? 'xss.jsonld' : `xss.jsonld.${it.index}`,
      it.severity === 'high' ? 'JSON-LD script breakout (stored XSS)' : 'JSON-LD not <-escaped (stored-XSS risk)',
      it.severity,
      false,
      it.detail,
      FIX,
    ),
  );
}
