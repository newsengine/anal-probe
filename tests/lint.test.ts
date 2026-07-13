// tests/lint.test.ts — keeps the whole codebase ESLint-clean as part of `npm test`.
// Runs the same `eslint .` the `lint` script does, so a lint regression fails the suite like any
// other test (rather than only being caught by a separate CI step someone has to remember to add).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const eslintBin = path.join(root, 'node_modules', 'eslint', 'bin', 'eslint.js');

test('eslint: the codebase is lint-clean', () => {
  try {
    execFileSync(process.execPath, [eslintBin, '.'], { cwd: root, stdio: 'pipe' });
  } catch (err) {
    const e = err as { stdout?: Buffer; stderr?: Buffer };
    const out = `${e.stdout?.toString() ?? ''}${e.stderr?.toString() ?? ''}`.trim();
    assert.fail(`ESLint reported problems (run \`npm run lint\`, or \`npm run lint:fix\` to auto-fix):\n${out}`);
  }
});
