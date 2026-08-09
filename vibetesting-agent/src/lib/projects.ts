import { eq, and, desc } from 'drizzle-orm';
import { getDb, schema } from './db';
import { id, token } from './ids';
import { assertCanCreateProject } from './entitlements';
import { hostnameFromUrl } from './dns-verify';
import { verifyProjectOwnership, type OwnershipMethod } from './ownership';
import { audit } from './audit';
import type { User, Project } from './db/schema';
import type { Policy } from './plans';

export async function listProjects(userId: string): Promise<Project[]> {
  const db = await getDb();
  return db
    .select()
    .from(schema.projects)
    .where(eq(schema.projects.userId, userId))
    .orderBy(desc(schema.projects.updatedAt));
}

export async function getProject(userId: string, projectId: string): Promise<Project | null> {
  const db = await getDb();
  const rows = await db
    .select()
    .from(schema.projects)
    .where(and(eq(schema.projects.id, projectId), eq(schema.projects.userId, userId)))
    .limit(1);
  return rows[0] ?? null;
}

export async function getProjectByShareToken(shareToken: string): Promise<Project | null> {
  const db = await getDb();
  const rows = await db.select().from(schema.projects).where(eq(schema.projects.shareToken, shareToken)).limit(1);
  return rows[0] ?? null;
}

export async function getProjectByWebhookSecret(secret: string): Promise<Project | null> {
  const db = await getDb();
  const rows = await db
    .select()
    .from(schema.projects)
    .where(eq(schema.projects.deployWebhookSecret, secret))
    .limit(1);
  return rows[0] ?? null;
}

export async function createProject(
  user: User,
  input: { name: string; url: string; policy?: Policy },
): Promise<Project> {
  await assertCanCreateProject(user);
  let url = input.url.trim();
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  const hostname = hostnameFromUrl(url);
  const db = await getDb();
  const now = new Date();
  const projectId = id('prj');
  await db.insert(schema.projects).values({
    id: projectId,
    userId: user.id,
    name: input.name.trim() || hostname,
    url,
    hostname,
    verified: false,
    verifyToken: token(16),
    policy: input.policy || 'ship',
    shipCheckEnabled: true,
    deployWebhookSecret: token(24),
    shareToken: token(18),
    badgePublic: true,
    createdAt: now,
    updatedAt: now,
  });
  await audit('project.created', { userId: user.id, target: projectId, detail: { url, hostname } });
  const rows = await db.select().from(schema.projects).where(eq(schema.projects.id, projectId)).limit(1);
  return rows[0]!;
}

export async function verifyProject(
  user: User,
  projectId: string,
  method: OwnershipMethod = 'dns',
): Promise<Project> {
  const project = await getProject(user.id, projectId);
  if (!project) throw new Error('Project not found');
  const result = await verifyProjectOwnership(user, project, method);
  return result.project;
}

export async function updateProject(
  userId: string,
  projectId: string,
  patch: Partial<{
    name: string;
    url: string;
    policy: Policy;
    shipCheckEnabled: boolean;
    githubRepo: string | null;
    badgePublic: boolean;
  }>,
): Promise<Project> {
  const project = await getProject(userId, projectId);
  if (!project) throw new Error('Project not found');
  const db = await getDb();
  const updates: Record<string, unknown> = { updatedAt: new Date() };
  if (patch.name !== undefined) updates.name = patch.name;
  if (patch.policy !== undefined) updates.policy = patch.policy;
  if (patch.shipCheckEnabled !== undefined) updates.shipCheckEnabled = patch.shipCheckEnabled;
  if (patch.githubRepo !== undefined) updates.githubRepo = patch.githubRepo;
  if (patch.badgePublic !== undefined) updates.badgePublic = patch.badgePublic;
  if (patch.url !== undefined) {
    let url = patch.url.trim();
    if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
    updates.url = url;
    updates.hostname = hostnameFromUrl(url);
    updates.verified = false;
    updates.verifiedAt = null;
  }
  await db.update(schema.projects).set(updates).where(eq(schema.projects.id, projectId));
  return (await getProject(userId, projectId))!;
}

export async function deleteProject(userId: string, projectId: string): Promise<void> {
  const project = await getProject(userId, projectId);
  if (!project) throw new Error('Project not found');
  const db = await getDb();
  await db.delete(schema.projects).where(eq(schema.projects.id, projectId));
  await audit('project.deleted', { userId, target: projectId });
}
