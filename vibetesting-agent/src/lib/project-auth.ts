/**
 * Opt-in authenticated scan access for a project.
 * User creates a dedicated test account on their app, confirms email, logs in,
 * then stores a session cookie / bearer token (password optional for docs).
 */
import { eq } from 'drizzle-orm';
import { getDb, schema } from './db';
import { getProject } from './projects';
import { sealSecret, unsealSecret } from './secret-box';
import { audit } from './audit';
import { assertSafeScanUrl } from './url-safety';
import type { Project, User } from './db/schema';

export type AuthMode = 'cookie' | 'bearer' | 'password';

export type AuthPublicStatus = {
  enabled: boolean;
  mode: AuthMode | null;
  email: string | null;
  loginUrl: string | null;
  hasSecret: boolean;
  verifiedAt: string | null;
  updatedAt: string | null;
  /** Ready for authenticated scans */
  ready: boolean;
};

export function authPublicStatus(project: Project): AuthPublicStatus {
  const enabled = Boolean(project.authEnabled);
  const hasSecret = Boolean(project.authSecretEnc);
  const verifiedAt = project.authVerifiedAt
    ? new Date(project.authVerifiedAt).toISOString()
    : null;
  return {
    enabled,
    mode: (project.authMode as AuthMode) || null,
    email: project.authEmail,
    loginUrl: project.authLoginUrl,
    hasSecret,
    verifiedAt,
    updatedAt: project.authUpdatedAt ? new Date(project.authUpdatedAt).toISOString() : null,
    ready: enabled && hasSecret && Boolean(project.authVerifiedAt),
  };
}

/** Build request headers for same-origin authenticated scans. */
export async function resolveAuthHeaders(project: Project): Promise<Record<string, string> | null> {
  if (!project.authEnabled || !project.authSecretEnc || !project.authMode) return null;
  try {
    const secret = await unsealSecret(project.authSecretEnc);
    if (project.authMode === 'cookie') {
      return { cookie: secret, 'user-agent': 'VibeTestingAgent/1.0 (+authenticated)' };
    }
    if (project.authMode === 'bearer') {
      const token = secret.startsWith('Bearer ') ? secret.slice(7) : secret;
      return {
        authorization: `Bearer ${token}`,
        'user-agent': 'VibeTestingAgent/1.0 (+authenticated)',
      };
    }
    if (project.authMode === 'password') {
      // Prefer cookie field if JSON payload includes sessionCookie after login helper
      try {
        const parsed = JSON.parse(secret) as { email?: string; password?: string; cookie?: string };
        if (parsed.cookie) {
          return { cookie: parsed.cookie, 'user-agent': 'VibeTestingAgent/1.0 (+authenticated)' };
        }
        // Fallback: HTTP Basic (works for some apps / gateways)
        if (parsed.email && parsed.password) {
          const basic = btoa(`${parsed.email}:${parsed.password}`);
          return {
            authorization: `Basic ${basic}`,
            'user-agent': 'VibeTestingAgent/1.0 (+authenticated)',
          };
        }
      } catch {
        /* plain password without JSON — not usable alone */
      }
    }
  } catch {
    return null;
  }
  return null;
}

export async function saveProjectAuth(
  user: User,
  projectId: string,
  input: {
    enabled: boolean;
    mode: AuthMode;
    email?: string | null;
    secret?: string | null;
    loginUrl?: string | null;
    /** Skip re-encrypt if secret omitted and keep existing */
    keepExistingSecret?: boolean;
  },
): Promise<Project> {
  const project = await getProject(user.id, projectId);
  if (!project) throw new Error('Project not found');

  const now = new Date();
  let secretEnc = project.authSecretEnc;
  if (input.secret && input.secret.trim()) {
    secretEnc = await sealSecret(input.secret.trim());
  } else if (!input.keepExistingSecret && input.enabled && !secretEnc) {
    throw new Error('Provide a session cookie, bearer token, or test password.');
  }

  let loginUrl = input.loginUrl?.trim() || project.authLoginUrl;
  if (loginUrl) {
    const safe = assertSafeScanUrl(loginUrl);
    if (!safe.ok) throw new Error(`Login URL not allowed: ${safe.reason}`);
    // Must be same host as project
    if (safe.hostname !== project.hostname && !safe.hostname.endsWith(`.${project.hostname}`)) {
      // allow exact project host or subdomain of project host only if project is apex
      if (safe.hostname !== project.hostname) {
        const projHost = project.hostname.replace(/^www\./, '');
        if (safe.hostname !== projHost && !safe.hostname.endsWith(`.${projHost}`)) {
          throw new Error('Login URL must be on the same domain as the project.');
        }
      }
    }
    loginUrl = safe.url;
  }

  const db = await getDb();
  await db
    .update(schema.projects)
    .set({
      authEnabled: input.enabled,
      authMode: input.mode,
      authEmail: input.email?.trim() || null,
      authSecretEnc: input.enabled ? secretEnc : null,
      authLoginUrl: loginUrl || null,
      // clear verified until they re-verify after change
      authVerifiedAt:
        input.secret && input.secret.trim() ? null : project.authVerifiedAt,
      authUpdatedAt: now,
      updatedAt: now,
    })
    .where(eq(schema.projects.id, projectId));

  await audit('project.auth_saved', {
    userId: user.id,
    target: projectId,
    detail: {
      enabled: input.enabled,
      mode: input.mode,
      email: input.email || null,
      secretUpdated: Boolean(input.secret?.trim()),
    },
  });

  return (await getProject(user.id, projectId))!;
}

export async function clearProjectAuth(user: User, projectId: string): Promise<Project> {
  const project = await getProject(user.id, projectId);
  if (!project) throw new Error('Project not found');
  const db = await getDb();
  const now = new Date();
  await db
    .update(schema.projects)
    .set({
      authEnabled: false,
      authMode: null,
      authEmail: null,
      authSecretEnc: null,
      authLoginUrl: null,
      authVerifiedAt: null,
      authUpdatedAt: now,
      updatedAt: now,
    })
    .where(eq(schema.projects.id, projectId));
  await audit('project.auth_cleared', { userId: user.id, target: projectId });
  return (await getProject(user.id, projectId))!;
}

/**
 * Probe project URL with stored credentials.
 * Heuristic: 401/403 = fail; redirect to login path = fail; otherwise pass.
 */
export async function verifyProjectAuth(
  user: User,
  projectId: string,
): Promise<{ ok: boolean; detail: string; status?: number }> {
  const project = await getProject(user.id, projectId);
  if (!project) throw new Error('Project not found');
  if (!project.authEnabled || !project.authSecretEnc) {
    return { ok: false, detail: 'Enable authenticated testing and save credentials first.' };
  }

  const headers = await resolveAuthHeaders(project);
  if (!headers) {
    return {
      ok: false,
      detail:
        'Could not build auth headers. For password mode, also paste a session cookie after logging in, or use cookie/bearer mode.',
    };
  }

  const target = project.authLoginUrl || project.url;
  const safe = assertSafeScanUrl(target);
  if (!safe.ok) return { ok: false, detail: safe.reason };

  let res: Response;
  try {
    res = await fetch(safe.url, {
      redirect: 'manual',
      headers: {
        ...headers,
        accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
      },
      signal: AbortSignal.timeout(12_000),
    });
  } catch (e) {
    return { ok: false, detail: `Fetch failed: ${(e as Error).message}` };
  }

  const loc = (res.headers.get('location') || '').toLowerCase();
  const looksLoginRedirect =
    res.status >= 300 &&
    res.status < 400 &&
    /login|signin|sign-in|auth|sso|session/.test(loc);

  if (res.status === 401 || res.status === 403) {
    return {
      ok: false,
      status: res.status,
      detail: `Server returned ${res.status} — session may be invalid or not authorized for this URL.`,
    };
  }
  if (looksLoginRedirect) {
    return {
      ok: false,
      status: res.status,
      detail: `Redirected to login (${loc.slice(0, 80)}). Cookie/token may be expired.`,
    };
  }

  const db = await getDb();
  const now = new Date();
  await db
    .update(schema.projects)
    .set({ authVerifiedAt: now, authUpdatedAt: now, updatedAt: now })
    .where(eq(schema.projects.id, projectId));

  await audit('project.auth_verified', {
    userId: user.id,
    target: projectId,
    detail: { status: res.status, mode: project.authMode },
  });

  return {
    ok: true,
    status: res.status,
    detail: `Looks authenticated (HTTP ${res.status}). Internal scans can attach this session.`,
  };
}
