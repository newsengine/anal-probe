// src/browser-auth.ts
// "Extra batteries" browser auth: launch an ISOLATED Chrome seeded with one of the user's real Chrome
// profiles' cookies, so an already-logged-in session drives a test WITHOUT handling passwords. Optional —
// needs `playwright-core` (dev/optional dep) + an installed Chrome; both are loaded lazily so the core
// zero-install scanner is unaffected. The user's live Chrome is never touched (we copy into a throwaway
// user-data-dir; macOS decrypts the cookies via the system Keychain as part of normal Chrome startup).

import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const CHROME_CANDIDATES = [
  process.env.CHROME_BIN,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium-browser',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
].filter(Boolean) as string[];

function chromeBin(): string | undefined { return CHROME_CANDIDATES.find((p) => { try { return fs.existsSync(p); } catch { return false; } }); }
function expand(p: string): string { return p.startsWith('~') ? path.join(os.homedir(), p.slice(1)) : p; }

/** Default Chrome profiles dir per-OS. */
export function defaultProfilesDir(): string {
  if (process.platform === 'darwin') return path.join(os.homedir(), 'Library/Application Support/Google/Chrome');
  if (process.platform === 'win32') return path.join(os.homedir(), 'AppData/Local/Google/Chrome/User Data');
  return path.join(os.homedir(), '.config/google-chrome');
}

/** Build a minimal throwaway user-data-dir seeded with just one source profile's cookies. */
export function seedProfile(profilesDir: string, srcProfile: string, tag: string): string {
  // Unique per-process dir so we never collide with a leftover dir a zombie Chrome still holds.
  const tmp = path.join(os.tmpdir(), `vibetesting-agent-auth-${tag}-${process.pid}`);
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best-effort */ }
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
  throw new Error(`no Cookies file found under ${srcDir} — check the profile name (e.g. "Profile 1")`);
}

export interface Session { browser: any; close: () => Promise<void> }

/** Launch isolated Chrome for a profile and connect Playwright over CDP. Caller must close(). */
export async function launchProfile(opts: { profilesDir: string; srcProfile: string; tag: string; port: number }): Promise<Session> {
  let chromium: any;
  try { ({ chromium } = await import('playwright-core')); }
  catch { throw new Error('browser auth needs playwright-core — run: npm i -D playwright-core'); }
  const bin = chromeBin();
  if (!bin) throw new Error('Google Chrome not found — install it or set CHROME_BIN');

  const userDataDir = seedProfile(opts.profilesDir, opts.srcProfile, opts.tag);
  const child = execFile(bin, [
    `--user-data-dir=${userDataDir}`,
    `--remote-debugging-port=${opts.port}`,
    '--no-first-run', '--no-default-browser-check', '--no-startup-window',
    '--disable-sync', '--disable-extensions', '--disable-background-networking',
  ], () => {});
  for (let i = 0; i < 40; i++) {
    try { if ((await fetch(`http://localhost:${opts.port}/json/version`)).ok) break; } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  const browser = await chromium.connectOverCDP(`http://localhost:${opts.port}`);
  return {
    browser,
    async close() {
      try { await browser.close(); } catch {}
      try { child.kill(); } catch {}
      try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch { /* best-effort */ }
    },
  };
}
