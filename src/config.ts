// src/config.ts
// Optional .analproberc.json for repeated/CI use: default flags so you don't retype them. CLI flags
// always override the file. Kept intentionally small — it only carries the knobs people repeat.

import { readFileSync } from 'node:fs';

export interface FileConfig {
  only?: string[];
  skip?: string[];
  failOn?: 'high' | 'medium' | 'any';
  corsPath?: string;
  rateLimitPath?: string;
  timeoutMs?: number;
  maxCrawl?: number;
  crawl?: number;
  allowReportOnlyCsp?: boolean;
  quiet?: boolean;
}

/**
 * Load config from an explicit path or the default `.analproberc.json` in cwd. A missing DEFAULT file is
 * fine (returns {}); a missing/invalid EXPLICIT path is an error the caller should surface.
 */
export function loadConfig(explicitPath?: string): { config: FileConfig; error?: string } {
  const path = explicitPath || '.analproberc.json';
  try {
    return { config: JSON.parse(readFileSync(path, 'utf8')) as FileConfig };
  } catch (e: any) {
    if (!explicitPath && e?.code === 'ENOENT') return { config: {} }; // no default file — fine
    return { config: {}, error: `could not read config ${path}: ${String(e?.message || e)}` };
  }
}
