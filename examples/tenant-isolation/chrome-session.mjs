// chrome-session.mjs — launch an ISOLATED Chrome seeded with one of your real Chrome profiles' cookies,
// so an already-logged-in session drives the test WITHOUT handling passwords. It copies only the
// profile's Cookies file into a throwaway user-data-dir (macOS decrypts them via the system Keychain as
// normal), launches system Chrome with a debug port, and connects over CDP. Your live Chrome is untouched.
//
// Requires: `npm i -D playwright-core` (uses your installed Google Chrome, no browser download).
// macOS paths are the default; adjust CHROME / profiles dir for Linux/Windows.

import { chromium } from 'playwright-core';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const CHROME = process.env.CHROME_BIN || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

function expand(p) { return p.startsWith('~') ? path.join(os.homedir(), p.slice(1)) : p; }

/** Build a minimal throwaway user-data-dir containing just one source profile's cookies. */
export function seedProfile(profilesDir, srcProfile, tag) {
  const tmp = path.join(os.tmpdir(), `vibetesting-agent-tenant-${tag}`);
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(path.join(tmp, 'Default', 'Network'), { recursive: true });
  const srcDir = path.join(expand(profilesDir), srcProfile);
  for (const rel of ['Cookies', 'Network/Cookies']) {
    const s = path.join(srcDir, rel);
    if (fs.existsSync(s)) {
      fs.copyFileSync(s, path.join(tmp, 'Default', 'Cookies'));
      fs.copyFileSync(s, path.join(tmp, 'Default', 'Network', 'Cookies'));
      return tmp;
    }
  }
  throw new Error(`no Cookies file found under ${srcDir}`);
}

/** Launch isolated Chrome for a profile and return a connected Playwright browser. Caller must close(). */
export async function launchProfile({ profilesDir, srcProfile, tag, port }) {
  const userDataDir = seedProfile(profilesDir, srcProfile, tag);
  const child = execFile(CHROME, [
    `--user-data-dir=${userDataDir}`,
    `--remote-debugging-port=${port}`,
    '--no-first-run', '--no-default-browser-check', '--no-startup-window',
    '--disable-sync', '--disable-extensions', '--disable-background-networking',
  ], () => {});
  for (let i = 0; i < 40; i++) {
    try { if ((await fetch(`http://localhost:${port}/json/version`)).ok) break; } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  const browser = await chromium.connectOverCDP(`http://localhost:${port}`);
  return {
    browser,
    async close() { try { await browser.close(); } catch {} try { child.kill(); } catch {} fs.rmSync(userDataDir, { recursive: true, force: true }); },
  };
}
