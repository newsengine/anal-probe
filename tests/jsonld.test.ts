import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanJsonLdBreakout } from '../dist/jsonld.js';

const ldBlock = (inner: string) =>
  `<!doctype html><html><head><script type="application/ld+json">${inner}</script></head><body></body></html>`;

test('clean, <-escaped JSON-LD → no issue', () => {
  const html = ldBlock('{"@context":"https://schema.org","@type":"Article","headline":"A safe headline"}');
  assert.equal(scanJsonLdBreakout(html).length, 0);
});

test('escaped tag content (\\u003c) → no issue', () => {
  const html = ldBlock('{"@type":"Article","headline":"5 \\u003c 6 rules"}');
  assert.equal(scanJsonLdBreakout(html).length, 0);
});

test('ACTIVE breakout: injected </script> truncates the block → HIGH', () => {
  // What ships when JSON.stringify a value containing </script><script>… — the browser (and our
  // regex) close the ld+json at the first </script>, leaving invalid/truncated JSON.
  const html =
    '<script type="application/ld+json">{"@type":"Article","headline":"Pwn</script><script>alert(document.cookie)</script>"}</script>';
  const issues = scanJsonLdBreakout(html);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].severity, 'high');
});

test('unescaped emitter (raw tag-like <) even in valid JSON → MEDIUM (latent)', () => {
  const html = ldBlock('{"@type":"Article","headline":"read <b>this</b> now"}');
  const issues = scanJsonLdBreakout(html);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].severity, 'medium');
});

test('multiple blocks scored independently', () => {
  const html =
    ldBlock('{"@type":"Article","headline":"clean"}') +
    ldBlock('{"@type":"Product","name":"<script>x</script>"}');
  const issues = scanJsonLdBreakout(html);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].index, 2);
  assert.equal(issues[0].severity, 'high');
});

test('type attribute with single quotes + whitespace is matched', () => {
  const html = `<script  type='application/ld+json' >{"@type":"Thing","name":"a</script><script>b"}</script>`;
  assert.equal(scanJsonLdBreakout(html).length, 1);
});
