'use client';

import { useEffect, useState } from 'react';
import { CopyButton } from '@/components/forms';

const LITE_PROMPT_KEY = 'vta_lite_agent_prompt';

type Stored = {
  url?: string;
  grade?: string;
  score?: number;
  agentPrompt?: string;
  at?: number;
};

/** Surfaces a Claude/Codex fix prompt saved from the homepage lite scan after signup. */
export function LitePromptBanner() {
  const [stored, setStored] = useState<Stored | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(LITE_PROMPT_KEY);
      if (!raw) return;
      const data = JSON.parse(raw) as Stored;
      if (!data.agentPrompt) return;
      // Expire after 24h
      if (data.at && Date.now() - data.at > 24 * 60 * 60 * 1000) {
        sessionStorage.removeItem(LITE_PROMPT_KEY);
        return;
      }
      setStored(data);
      setOpen(true);
    } catch {
      /* ignore */
    }
  }, []);

  if (!stored?.agentPrompt || !open) return null;

  return (
    <div className="panel border-[var(--lime)]/40 p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="mono text-xs uppercase tracking-wider text-[var(--lime)]">
            Your lite-scan fix prompt
          </div>
          <h2 className="mono mt-1 text-lg font-bold">
            Claude / Codex pack ready
            {stored.url ? (
              <span className="block text-sm font-normal text-[var(--mut)] mono mt-1">{stored.url}</span>
            ) : null}
          </h2>
          <p className="mt-1 text-sm text-[var(--mut)]">
            Grade {stored.grade ?? '—'} · {stored.score ?? '—'}/100 — paste into Claude, Codex, or Cursor to
            fix ranked issues.
          </p>
        </div>
        <button
          type="button"
          className="btn-ghost text-xs"
          onClick={() => {
            setOpen(false);
            try {
              sessionStorage.removeItem(LITE_PROMPT_KEY);
            } catch {
              /* ignore */
            }
          }}
        >
          Dismiss
        </button>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <CopyButton text={stored.agentPrompt} label="Copy full Claude/Codex prompt" />
      </div>
      <pre className="mono mt-3 max-h-48 overflow-auto rounded-lg border border-[var(--edge)] bg-black/40 p-3 text-[11px] leading-relaxed whitespace-pre-wrap text-[var(--ink)]">
        {stored.agentPrompt}
      </pre>
    </div>
  );
}
