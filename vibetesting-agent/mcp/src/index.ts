#!/usr/bin/env node
/**
 * VibeTesting Agent MCP — Claude / Codex / Cursor tools for continuous ship scans.
 *
 * Env:
 *   VTA_API_URL  (default http://localhost:3000)
 *   VTA_API_KEY  (sk_live_… from dashboard)
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const API_URL = (process.env.VTA_API_URL || 'http://localhost:3000').replace(/\/$/, '');
const API_KEY = process.env.VTA_API_KEY || '';

async function api(path: string, init: RequestInit = {}) {
  if (!API_KEY) throw new Error('VTA_API_KEY is required');
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      'content-type': 'application/json',
      ...(init.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data as { error?: string }).error || `HTTP ${res.status}`);
  return data;
}

function text(data: unknown) {
  return {
    content: [{ type: 'text' as const, text: typeof data === 'string' ? data : JSON.stringify(data, null, 2) }],
  };
}

const server = new McpServer({
  name: 'vibetesting-agent',
  version: '0.1.0',
});

server.tool('list_projects', 'List VibeTesting Agent projects for the authenticated account', {}, async () => {
  const data = await api('/api/v1/projects');
  return text(data);
});

server.tool(
  'start_scan',
  'Start a security scan. Requires authorized=true confirming you may test the target.',
  {
    url: z.string().optional().describe('Target URL (if not using project_id)'),
    project_id: z.string().optional().describe('Existing project id'),
    mode: z.enum(['fast', 'full', 'crawl']).optional().describe('Scan depth'),
    authorized: z.boolean().describe('Must be true — you own or may test this target'),
  },
  async (args) => {
    if (!args.authorized) {
      return text({ error: 'authorized must be true' });
    }
    const data = await api('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify({
        url: args.url,
        projectId: args.project_id,
        mode: args.mode || 'fast',
        authorized: true,
        trigger: 'mcp',
      }),
    });
    return text(data);
  },
);

server.tool(
  'get_scan',
  'Get scan status, score, grade, summary, and findings',
  { scan_id: z.string() },
  async (args) => {
    const data = await api(`/api/v1/scans/${args.scan_id}`);
    return text(data);
  },
);

server.tool(
  'list_findings',
  'List failing findings for a scan, optionally filtered by severity',
  {
    scan_id: z.string(),
    severity: z.enum(['high', 'medium', 'low', 'info']).optional(),
  },
  async (args) => {
    const data = (await api(`/api/v1/scans/${args.scan_id}`)) as {
      scan?: { findings?: { pass: boolean; severity: string }[] };
    };
    let findings = (data.scan?.findings || []).filter((f) => !f.pass);
    if (args.severity) findings = findings.filter((f) => f.severity === args.severity);
    return text({ findings, count: findings.length });
  },
);

server.tool(
  'get_fix_prompt',
  'Get an agent-ready fix prompt for a full scan or a single finding',
  {
    scan_id: z.string(),
    finding_id: z.string().optional(),
  },
  async (args) => {
    const q = args.finding_id ? `?findingId=${encodeURIComponent(args.finding_id)}` : '';
    const data = await api(`/api/v1/scans/${args.scan_id}/fix-prompt${q}`);
    return text(data);
  },
);

server.tool(
  'get_security_review',
  'Get the Claude /security-review markdown produced at end of a completed scan (P1…Pn ranked report).',
  { scan_id: z.string() },
  async (args) => {
    const data = await api(`/api/v1/scans/${args.scan_id}/security-review`);
    return text(data);
  },
);

server.tool(
  'compare_baseline',
  'Show what is new vs the project baseline for a completed scan',
  { scan_id: z.string() },
  async (args) => {
    const data = (await api(`/api/v1/scans/${args.scan_id}`)) as {
      scan?: { baselineDiff?: unknown; grade?: string; score?: number };
    };
    return text({
      grade: data.scan?.grade,
      score: data.scan?.score,
      baselineDiff: data.scan?.baselineDiff,
    });
  },
);

server.tool(
  'get_badge_markdown',
  'Markdown badge for a project share token or project id',
  {
    project_id: z.string().optional(),
    share_token: z.string().optional(),
  },
  async (args) => {
    let shareToken = args.share_token;
    if (!shareToken && args.project_id) {
      const data = (await api(`/api/v1/projects/${args.project_id}`)) as {
        project?: { shareToken?: string };
      };
      shareToken = data.project?.shareToken;
    }
    if (!shareToken) return text({ error: 'project_id or share_token required' });
    const md = `![ship-score](${API_URL}/api/badge/${shareToken})`;
    return text({ markdown: md, badgeUrl: `${API_URL}/api/badge/${shareToken}` });
  },
);

server.tool('whoami', 'Show current VibeTesting Agent user and plan entitlements', {}, async () => {
  const data = await api('/api/v1/me');
  return text(data);
});

const transport = new StdioServerTransport();
await server.connect(transport);
