// src/config.ts
// Optional .analproberc.json for repeated/CI use: default flags so you don't retype them. CLI flags
// always override the file. Kept intentionally small — it only carries the knobs people repeat.
import { readFileSync } from 'node:fs';
/**
 * Load config from an explicit path or the default `.analproberc.json` in cwd. A missing DEFAULT file is
 * fine (returns {}); a missing/invalid EXPLICIT path is an error the caller should surface.
 */
export function loadConfig(explicitPath) {
    const path = explicitPath || '.analproberc.json';
    let config;
    try {
        config = JSON.parse(readFileSync(path, 'utf8'));
    }
    catch (e) {
        if (!explicitPath && e?.code === 'ENOENT')
            return { config: {} }; // no default file — fine
        return { config: {}, error: `could not read config ${path}: ${String(e?.message || e)}` };
    }
    // Validate the values we later trust as numbers/enums, so a bad file fails loudly, not silently.
    for (const k of ['crawl', 'maxCrawl', 'timeoutMs']) {
        const v = config[k];
        if (v !== undefined && (typeof v !== 'number' || !Number.isFinite(v) || v <= 0)) {
            return { config: {}, error: `config "${k}" must be a positive number (got ${JSON.stringify(v)})` };
        }
    }
    if (config.failOn !== undefined && !['high', 'medium', 'any'].includes(config.failOn)) {
        return { config: {}, error: `config "failOn" must be high|medium|any (got ${JSON.stringify(config.failOn)})` };
    }
    return { config };
}
