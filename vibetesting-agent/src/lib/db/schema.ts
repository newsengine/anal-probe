/**
 * VibeTesting Agent data model — users, projects, scans, billing entitlements, API keys, audit log.
 */
import { sqliteTable, text, integer, real, index, uniqueIndex } from 'drizzle-orm/sqlite-core';

export const users = sqliteTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  name: text('name'),
  image: text('image'),
  githubId: text('github_id').unique(),
  githubLogin: text('github_login'),
  stripeCustomerId: text('stripe_customer_id').unique(),
  plan: text('plan', { enum: ['free', 'weekly', 'daily', 'commit', 'vibe', 'studio'] })
    .notNull()
    .default('free'),
  planStatus: text('plan_status').notNull().default('active'), // active | past_due | canceled
  stripeSubscriptionId: text('stripe_subscription_id'),
  scansUsedMonth: integer('scans_used_month').notNull().default(0),
  crawlUsedMonth: integer('crawl_used_month').notNull().default(0),
  usageMonth: text('usage_month'), // YYYY-MM
  notifyEmail: integer('notify_email', { mode: 'boolean' }).notNull().default(true),
  slackWebhookUrl: text('slack_webhook_url'),
  /** Inbox ownership — set after click-to-verify or trusted IdP emailVerified */
  emailVerifiedAt: integer('email_verified_at', { mode: 'timestamp_ms' }),
  emailVerifyToken: text('email_verify_token'),
  emailVerifyExpiresAt: integer('email_verify_expires_at', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
});

export const sessions = sqliteTable('sessions', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
});

export const apiKeys = sqliteTable('api_keys', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  keyHash: text('key_hash').notNull().unique(),
  keyPrefix: text('key_prefix').notNull(), // sk_live_xxxx for display
  lastUsedAt: integer('last_used_at', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  revokedAt: integer('revoked_at', { mode: 'timestamp_ms' }),
}, (t) => [index('api_keys_user_idx').on(t.userId)]);

export const projects = sqliteTable('projects', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  url: text('url').notNull(),
  hostname: text('hostname').notNull(),
  verified: integer('verified', { mode: 'boolean' }).notNull().default(false),
  verifyToken: text('verify_token').notNull(),
  verifiedAt: integer('verified_at', { mode: 'timestamp_ms' }),
  /** How ownership was proven: dns | email */
  verifyMethod: text('verify_method'),
  policy: text('policy', { enum: ['chill', 'ship', 'client', 'launch'] }).notNull().default('ship'),
  shipCheckEnabled: integer('ship_check_enabled', { mode: 'boolean' }).notNull().default(true),
  deployWebhookSecret: text('deploy_webhook_secret').notNull(),
  githubRepo: text('github_repo'), // owner/name
  githubInstallationId: text('github_installation_id'),
  badgePublic: integer('badge_public', { mode: 'boolean' }).notNull().default(true),
  shareToken: text('share_token').notNull(),
  lastScore: integer('last_score'),
  lastGrade: text('last_grade'),
  lastScanAt: integer('last_scan_at', { mode: 'timestamp_ms' }),
  baselineJson: text('baseline_json'), // serialized failing finding ids
  /** Opt-in authenticated scans (test user session) */
  authEnabled: integer('auth_enabled', { mode: 'boolean' }).notNull().default(false),
  /** cookie | bearer | password (password stored for re-login docs; scans prefer cookie/bearer) */
  authMode: text('auth_mode'),
  authEmail: text('auth_email'),
  /** AES-GCM sealed secret (cookie, token, or password JSON) */
  authSecretEnc: text('auth_secret_enc'),
  authLoginUrl: text('auth_login_url'),
  authVerifiedAt: integer('auth_verified_at', { mode: 'timestamp_ms' }),
  authUpdatedAt: integer('auth_updated_at', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
}, (t) => [
  index('projects_user_idx').on(t.userId),
  uniqueIndex('projects_user_hostname_idx').on(t.userId, t.hostname),
]);

export const scans = sqliteTable('scans', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  projectId: text('project_id').references(() => projects.id, { onDelete: 'set null' }),
  url: text('url').notNull(),
  mode: text('mode', { enum: ['lite', 'fast', 'full', 'crawl'] }).notNull().default('fast'),
  trigger: text('trigger', {
    enum: ['manual', 'api', 'mcp', 'deploy', 'github', 'schedule', 'rescan'],
  }).notNull().default('manual'),
  status: text('status', {
    enum: ['queued', 'running', 'completed', 'failed', 'canceled'],
  }).notNull().default('queued'),
  authorized: integer('authorized', { mode: 'boolean' }).notNull().default(false),
  score: integer('score'),
  grade: text('grade'),
  summaryJson: text('summary_json'),
  findingsJson: text('findings_json'),
  fixPackMarkdown: text('fix_pack_markdown'),
  reportHtml: text('report_html'),
  baselineDiffJson: text('baseline_diff_json'),
  error: text('error'),
  startedAt: integer('started_at', { mode: 'timestamp_ms' }),
  finishedAt: integer('finished_at', { mode: 'timestamp_ms' }),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  metaJson: text('meta_json'), // github sha, pr number, etc.
}, (t) => [
  index('scans_user_idx').on(t.userId),
  index('scans_project_idx').on(t.projectId),
  index('scans_status_idx').on(t.status),
]);

export const auditLog = sqliteTable('audit_log', {
  id: text('id').primaryKey(),
  userId: text('user_id'),
  action: text('action').notNull(),
  target: text('target'),
  detailJson: text('detail_json'),
  ip: text('ip'),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
}, (t) => [index('audit_user_idx').on(t.userId), index('audit_created_idx').on(t.createdAt)]);

export const rateLimits = sqliteTable('rate_limits', {
  key: text('key').primaryKey(),
  count: integer('count').notNull().default(0),
  windowStart: integer('window_start', { mode: 'timestamp_ms' }).notNull(),
});

export type User = typeof users.$inferSelect;
export type Project = typeof projects.$inferSelect;
export type Scan = typeof scans.$inferSelect;
export type ApiKey = typeof apiKeys.$inferSelect;
