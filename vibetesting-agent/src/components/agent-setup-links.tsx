'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';

const CLAUDE_LOGO = 'https://cdn.simpleicons.org/claude/D97757';
const OPENAI_LOGO = 'https://cdn.simpleicons.org/openai/10A37F';

type AgentKind = 'claude' | 'codex';

const APP_URL =
  (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_APP_URL) ||
  'https://vibetestingagent.com';

function claudeSnippet(apiUrl: string, apiKey: string) {
  return `# VibeTesting Agent → Claude Code MCP
# 1) Keep this terminal in a folder that has mcp/src/index.ts
#    (clone: ${APP_URL.replace('https://', 'https://github.com/')}  or monorepo vibetesting-agent/)
# 2) Run:

export VTA_API_URL=${apiUrl}
export VTA_API_KEY=${apiKey}

claude mcp add vibetesting-agent \\
  --env VTA_API_URL=${apiUrl} \\
  --env VTA_API_KEY=${apiKey} \\
  -- npx -y tsx mcp/src/index.ts

# 3) Confirm tools: claude mcp list
# 4) After a deploy scan: get_security_review / get_fix_prompt`;
}

function codexSnippet(apiUrl: string, apiKey: string) {
  return `# VibeTesting Agent → OpenAI Codex / Cursor MCP
# Add a stdio MCP server (config.toml / Cursor MCP settings):

{
  "mcpServers": {
    "vibetesting-agent": {
      "command": "npx",
      "args": ["-y", "tsx", "mcp/src/index.ts"],
      "cwd": "/absolute/path/to/vibetesting-agent",
      "env": {
        "VTA_API_URL": "${apiUrl}",
        "VTA_API_KEY": "${apiKey}"
      }
    }
  }
}

# Codex CLI install: https://developers.openai.com/codex/cli
# Then open your project and use vibetesting-agent tools
# (start_scan, get_scan, get_security_review, get_fix_prompt).`;
}

function AgentConnectModal({
  agent,
  onClose,
}: {
  agent: AgentKind;
  onClose: () => void;
}) {
  const [phase, setPhase] = useState<'loading' | 'guest' | 'ready' | 'error'>('loading');
  const [email, setEmail] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const title = agent === 'claude' ? 'Claude Code' : 'OpenAI Codex';
  const logo = agent === 'claude' ? CLAUDE_LOGO : OPENAI_LOGO;
  const docs =
    agent === 'claude'
      ? 'https://docs.anthropic.com/en/docs/claude-code/mcp'
      : 'https://developers.openai.com/codex/cli';

  const checkAuth = useCallback(async () => {
    setPhase('loading');
    setError('');
    try {
      const res = await fetch('/api/v1/me', { credentials: 'include' });
      if (res.status === 401) {
        setPhase('guest');
        return;
      }
      if (!res.ok) {
        setError(`Could not load account (${res.status})`);
        setPhase('error');
        return;
      }
      const data = await res.json();
      setEmail(data.email || data.name || 'signed in');
      setPhase('ready');
    } catch {
      setError('Network error checking session');
      setPhase('error');
    }
  }, []);

  useEffect(() => {
    void checkAuth();
  }, [checkAuth]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  async function generateKey() {
    setBusy(true);
    setError('');
    try {
      const res = await fetch('/api/v1/keys', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: agent === 'claude' ? 'Claude Code MCP' : 'Codex MCP',
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || `Could not create API key (${res.status})`);
        return;
      }
      if (!data.secret) {
        setError('API key was created but secret was not returned');
        return;
      }
      setApiKey(data.secret as string);
    } catch {
      setError('Network error creating API key');
    } finally {
      setBusy(false);
    }
  }

  const snippet =
    apiKey &&
    (agent === 'claude' ? claudeSnippet(APP_URL, apiKey) : codexSnippet(APP_URL, apiKey));

  async function copySnippet() {
    if (!snippet) return;
    try {
      await navigator.clipboard.writeText(snippet);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError('Could not copy — select the text manually');
    }
  }

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="agent-connect-title"
    >
      <button
        type="button"
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        aria-label="Close"
        onClick={onClose}
      />
      <div className="relative z-10 max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-2xl border border-[var(--edge)] bg-[var(--bg)] p-6 shadow-2xl shadow-black/50">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={logo} alt="" width={28} height={28} className="h-7 w-7" />
            <div>
              <h2 id="agent-connect-title" className="mono text-lg font-bold text-[var(--ink)]">
                Connect {title}
              </h2>
              <p className="text-xs text-[var(--mut)]">VibeTesting Agent MCP · full suite + fix loop</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg px-2 py-1 text-sm text-[var(--mut)] hover:bg-white/5 hover:text-[var(--ink)]"
          >
            ✕
          </button>
        </div>

        {phase === 'loading' && (
          <p className="mt-6 text-sm text-[var(--mut)]">Checking your account…</p>
        )}

        {phase === 'guest' && (
          <div className="mt-6 space-y-4">
            <p className="text-sm text-[var(--mut)]">
              Create a free account (or sign in) so we can generate a personal API key and the exact{' '}
              {title} connection snippet for your workspace.
            </p>
            <div className="flex flex-wrap gap-3">
              <Link href="/login" className="btn-primary" onClick={onClose}>
                Create account / Sign in
              </Link>
              <a
                href={docs}
                target="_blank"
                rel="noreferrer"
                className="btn-ghost text-xs"
              >
                {title} docs ↗
              </a>
            </div>
            <p className="text-xs text-[var(--mut)]">
              After login, click the {title} button again to generate your custom connection.
            </p>
          </div>
        )}

        {phase === 'ready' && (
          <div className="mt-6 space-y-4">
            <p className="text-sm text-[var(--mut)]">
              Signed in as <span className="text-[var(--ink)]">{email}</span>. Generate a one-time API
              key and copy the {title} setup below.
            </p>

            {!apiKey ? (
              <button
                type="button"
                className="btn-primary w-full"
                disabled={busy}
                onClick={() => void generateKey()}
              >
                {busy ? 'Generating…' : `Generate ${title} connection`}
              </button>
            ) : (
              <>
                <div className="rounded-lg border border-[var(--md)]/40 bg-[var(--md)]/10 px-3 py-2 text-xs text-[var(--md)]">
                  API key shown once. Store it now — it will not be displayed again.
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="mono text-xs text-[var(--lime)]">Connection snippet</span>
                  <button type="button" className="btn-ghost !py-1 !px-3 text-xs" onClick={() => void copySnippet()}>
                    {copied ? 'Copied' : 'Copy all'}
                  </button>
                </div>
                <pre className="mono max-h-64 overflow-auto whitespace-pre-wrap rounded-lg bg-black/50 p-3 text-[11px] leading-relaxed text-[var(--mut)]">
                  {snippet}
                </pre>
                <div className="flex flex-wrap gap-2">
                  <a href={docs} target="_blank" rel="noreferrer" className="btn-ghost text-xs">
                    {title} docs ↗
                  </a>
                  <Link href="/dashboard/mcp" className="btn-ghost text-xs" onClick={onClose}>
                    Full MCP guide
                  </Link>
                  <Link href="/dashboard/keys" className="btn-ghost text-xs" onClick={onClose}>
                    Manage API keys
                  </Link>
                </div>
              </>
            )}
          </div>
        )}

        {phase === 'error' && (
          <div className="mt-6 space-y-3">
            <p className="text-sm text-[var(--hi)]">{error || 'Something went wrong'}</p>
            <button type="button" className="btn-ghost" onClick={() => void checkAuth()}>
              Retry
            </button>
          </div>
        )}

        {error && phase === 'ready' && (
          <p className="mt-3 text-sm text-[var(--hi)]">{error}</p>
        )}
      </div>
    </div>
  );
}

/** Claude Code + OpenAI Codex setup chips — shown on every page via root layout. */
export function AgentSetupLinks({ compact = false }: { compact?: boolean }) {
  const [open, setOpen] = useState<AgentKind | null>(null);

  return (
    <>
      <div
        className={
          compact
            ? 'flex flex-wrap items-center gap-2'
            : 'flex flex-wrap items-center justify-center gap-3 sm:justify-start'
        }
      >
        {!compact && (
          <span className="mono text-[10px] uppercase tracking-[0.14em] text-[var(--mut)]">
            Connect agents
          </span>
        )}
        <button
          type="button"
          onClick={() => setOpen('claude')}
          className="inline-flex items-center gap-2 rounded-full border border-[var(--edge)] bg-black/30 px-3 py-1.5 text-xs font-medium text-[var(--ink)] transition hover:border-[var(--lime)]/50 hover:text-[var(--lime)]"
          title="Connect Claude Code to VibeTesting Agent"
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={CLAUDE_LOGO} alt="" width={16} height={16} className="h-4 w-4" />
          Claude Code
        </button>
        <button
          type="button"
          onClick={() => setOpen('codex')}
          className="inline-flex items-center gap-2 rounded-full border border-[var(--edge)] bg-black/30 px-3 py-1.5 text-xs font-medium text-[var(--ink)] transition hover:border-[var(--lime)]/50 hover:text-[var(--lime)]"
          title="Connect OpenAI Codex to VibeTesting Agent"
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={OPENAI_LOGO} alt="" width={16} height={16} className="h-4 w-4" />
          Codex
        </button>
        <Link
          href="/dashboard/mcp"
          className="inline-flex items-center gap-1.5 rounded-full border border-[var(--lime)]/30 bg-[var(--lime)]/10 px-3 py-1.5 text-xs font-medium text-[var(--lime)] transition hover:bg-[var(--lime)]/20"
          title="Full Claude / Codex MCP guide"
        >
          Full MCP guide →
        </Link>
      </div>
      {open && <AgentConnectModal agent={open} onClose={() => setOpen(null)} />}
    </>
  );
}

/** Full-width strip used in root layout (every page). */
export function AgentSetupBar() {
  return (
    <div className="border-b border-[var(--edge)] bg-[var(--panel)]/80 backdrop-blur-sm">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-5 py-2.5">
        <AgentSetupLinks />
        <p className="hidden text-[11px] text-[var(--mut)] md:block">
          Auto-scan on deploy · recursive fix with Claude or Codex
        </p>
      </div>
    </div>
  );
}

export function SiteFooter() {
  return (
    <footer className="mt-auto border-t border-[var(--edge)] bg-black/20">
      <div className="mx-auto flex max-w-6xl flex-col gap-4 px-5 py-8 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="mono text-sm font-bold text-[var(--ink)]">VibeTesting Agent</div>
          <p className="mt-1 text-xs text-[var(--mut)]">
            Ship with vibe. Scan before bad guys do.
          </p>
        </div>
        <AgentSetupLinks />
      </div>
      <div className="border-t border-[var(--edge)] py-3 text-center text-[11px] text-[var(--mut)]">
        <Link href="/docs" className="hover:text-[var(--lime)]">
          Docs
        </Link>
        {' · '}
        <Link href="/docs/coverage" className="hover:text-[var(--lime)]">
          Coverage
        </Link>
        {' · '}
        <Link href="/pricing" className="hover:text-[var(--lime)]">
          Pricing
        </Link>
        {' · '}
        <Link href="/legal/terms" className="hover:text-[var(--lime)]">
          Terms
        </Link>
        {' · '}
        <Link href="/dashboard/mcp" className="hover:text-[var(--lime)]">
          Claude / Codex
        </Link>
      </div>
    </footer>
  );
}
