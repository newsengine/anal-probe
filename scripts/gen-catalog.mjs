#!/usr/bin/env node
// scripts/gen-catalog.mjs
// Regenerate docs/CHECKS.md from the canonical catalog in src/catalog.ts. Run `npm run catalog`
// (which builds first). tests/catalog.test.ts fails if the committed docs/CHECKS.md is stale, so this
// is the one command to run after adding or upgrading a check.

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { renderCatalogMarkdown } from '../dist/catalog.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_FILE = join(__dirname, '..', 'docs', 'CHECKS.md');

writeFileSync(OUT_FILE, renderCatalogMarkdown());
console.log(`wrote ${OUT_FILE}`);
