// src/agent.ts
// "Agent-readiness": is this deployed site consumable by AI agents / LLM crawlers? All black-box from
// the already-fetched HTML plus a few cheap GETs (llms.txt, robots.txt, .well-known) — no browser, so
// it stays in the zero-dep model. The grading is split into a pure function (evaluateAgentReadiness) so
// it unit-tests without the network, mirroring dns.ts.

import type { Finding, ScanContext, Severity } from './types.js';
import { safeFetch } from './core.js';

const f = (id: string, title: string, severity: Severity, pass: boolean, detail: string, fix?: string): Finding =>
  ({ category: 'agent', id, title, severity, pass, detail, fix });

// The crawlers that matter for AI/LLM answer engines. Lowercased for case-insensitive matching.
export const AI_CRAWLERS = [
  'gptbot', 'oai-searchbot', 'chatgpt-user', 'claudebot', 'claude-web', 'anthropic-ai',
  'perplexitybot', 'google-extended', 'ccbot', 'bytespider', 'amazonbot', 'applebot-extended',
  'meta-externalagent', 'cohere-ai',
];

/** Visible text an agent would read if it does NOT execute JavaScript (strips script/style/tags/entities). */
export function visibleText(html: string): string {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z#0-9]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Parse robots.txt and return which of `uaList` are blocked from the site root. A UA is "blocked" when
 * the group that applies to it (its own, else the `*` wildcard) contains `Disallow: /`. Groups are the
 * standard robots.txt records: one or more consecutive `User-agent:` lines followed by rules.
 */
export function aiCrawlersBlocked(robotsTxt: string, uaList: string[] = AI_CRAWLERS): string[] {
  // Build UA -> "is Disallow: / present in its group" map.
  const groups: { agents: string[]; blocksRoot: boolean }[] = [];
  let current: { agents: string[]; blocksRoot: boolean } | null = null;
  let sawRuleSincePrevAgent = false;
  for (const rawLine of robotsTxt.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const m = line.match(/^(user-agent|disallow|allow)\s*:\s*(.*)$/i);
    if (!m) continue;
    const field = m[1].toLowerCase();
    const value = m[2].trim();
    if (field === 'user-agent') {
      // A User-agent after a rule line starts a NEW group.
      if (!current || sawRuleSincePrevAgent) { current = { agents: [], blocksRoot: false }; groups.push(current); sawRuleSincePrevAgent = false; }
      current.agents.push(value.toLowerCase());
    } else if (current) {
      sawRuleSincePrevAgent = true;
      if (field === 'disallow' && value === '/') current.blocksRoot = true;
    }
  }

  const groupFor = (ua: string) => groups.find((g) => g.agents.includes(ua)) ?? groups.find((g) => g.agents.includes('*'));
  const blocked: string[] = [];
  for (const ua of uaList) {
    const g = groupFor(ua);
    if (g?.blocksRoot) blocked.push(ua);
  }
  return blocked;
}

export interface AgentReadinessInput {
  html: string;
  /** true if /llms.txt is present and looks like text/markdown (not an SPA HTML fallback). */
  hasLlmsTxt: boolean;
  /** robots.txt body ('' if none). */
  robotsTxt: string;
  robotsPresent: boolean;
  /** true if an MCP / ai-plugin manifest is discoverable under /.well-known. */
  hasAgentManifest: boolean;
}

/** Pure grader → deterministic, network-free, fully unit-testable. */
export function evaluateAgentReadiness(inp: AgentReadinessInput): Finding[] {
  const out: Finding[] = [];

  // 1. Content is server-rendered (an agent that can't run JS still gets your content).
  const text = visibleText(inp.html);
  const jsOnly = text.length < 250 && /<script\b/i.test(inp.html);
  out.push(f('agent.ssr-content',
    jsOnly ? 'Content is JavaScript-only (agents may see an empty page)' : 'Content is server-rendered',
    'medium', !jsOnly,
    jsOnly ? `only ${text.length} chars of text in the raw HTML — agents/LLMs that don't execute JS see a near-empty shell` : `${text.length} chars of readable text in the initial HTML`,
    jsOnly ? 'Server-render or pre-render the important content (SSR/SSG) so crawlers and agents can read it without running JavaScript.' : undefined));

  // 2. llms.txt — the emerging standard for agent-facing site guidance.
  out.push(f('agent.llms-txt', inp.hasLlmsTxt ? 'Has /llms.txt' : 'No /llms.txt', 'low', inp.hasLlmsTxt,
    inp.hasLlmsTxt ? '/llms.txt is served' : 'no /llms.txt found',
    inp.hasLlmsTxt ? undefined : 'Add a /llms.txt (Markdown) summarising your site + key links so AI agents can navigate it. See llmstxt.org.'));

  // 3. AI-crawler policy in robots.txt (report blocks; may be intentional, so keep it low).
  if (inp.robotsPresent) {
    const blocked = aiCrawlersBlocked(inp.robotsTxt);
    out.push(f('agent.ai-crawlers',
      blocked.length ? `robots.txt blocks ${blocked.length} AI crawler(s)` : 'robots.txt allows AI crawlers',
      'low', blocked.length === 0,
      blocked.length ? `blocked at /: ${blocked.slice(0, 8).join(', ')}` : 'no AI crawler is Disallowed from the site root',
      blocked.length ? 'If you WANT to appear in AI answers, remove the Disallow for these agents. (Ignore this if blocking them is deliberate.)' : undefined));
  } else {
    out.push(f('agent.ai-crawlers', 'No robots.txt to declare crawler policy', 'low', false,
      'no robots.txt — crawler behaviour is undefined',
      'Add a robots.txt so you can explicitly allow (or block) AI crawlers like GPTBot/ClaudeBot.'));
  }

  // 4. Structured data (JSON-LD) — helps agents understand entities on the page.
  const hasJsonLd = /<script\b[^>]*type\s*=\s*["']application\/ld\+json["']/i.test(inp.html);
  out.push(f('agent.structured-data', hasJsonLd ? 'Has JSON-LD structured data' : 'No JSON-LD structured data', 'low', hasJsonLd,
    hasJsonLd ? 'schema.org JSON-LD present' : 'no <script type="application/ld+json">',
    hasJsonLd ? undefined : 'Add schema.org JSON-LD (Organization/Article/Product…) so agents can extract structured facts about your content.'));

  // 5. Agent/MCP manifest discovery — a bonus, purely informational.
  out.push(f('agent.manifest', inp.hasAgentManifest ? 'Has an agent/MCP manifest' : 'No agent/MCP manifest', 'info', inp.hasAgentManifest,
    inp.hasAgentManifest ? 'a /.well-known agent manifest is discoverable' : 'no /.well-known/mcp or ai-plugin manifest (optional)',
    inp.hasAgentManifest ? undefined : 'Optional: expose a /.well-known/ai-plugin.json or MCP manifest if you want agents to call your APIs directly.'));

  return out;
}

/** Gather the inputs (cheap GETs) and grade. */
export async function agentChecks(ctx: ScanContext): Promise<Finding[]> {
  if (!ctx.res) return [];

  const auth = ctx.opts.extraHeaders;
  const llmsRes = await safeFetch(ctx.origin + '/llms.txt', { redirect: 'follow', headers: auth });
  let hasLlmsTxt = false;
  if (llmsRes && llmsRes.ok) {
    const ct = (llmsRes.headers.get('content-type') || '').toLowerCase();
    const body = (await llmsRes.text()).slice(0, 2000);
    // Accept text/markdown; reject an SPA HTML catch-all masquerading as llms.txt.
    hasLlmsTxt = !/<html/i.test(body) && (ct.includes('text') || ct.includes('markdown') || body.trim().length > 0);
  }

  const robotsRes = await safeFetch(ctx.origin + '/robots.txt', { redirect: 'follow', headers: auth });
  const robotsPresent = !!(robotsRes && robotsRes.ok);
  const robotsTxt = robotsPresent ? (await robotsRes!.text()).slice(0, 20_000) : '';

  let hasAgentManifest = false;
  for (const p of ['/.well-known/ai-plugin.json', '/.well-known/mcp.json', '/.well-known/mcp']) {
    const r = await safeFetch(ctx.origin + p, { redirect: 'follow', headers: auth });
    if (r && r.ok) {
      const body = (await r.text()).slice(0, 1000);
      if (!/<html/i.test(body)) { hasAgentManifest = true; break; }
    }
  }

  return evaluateAgentReadiness({ html: ctx.html, hasLlmsTxt, robotsTxt, robotsPresent, hasAgentManifest });
}
