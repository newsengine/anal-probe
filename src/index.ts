// Public API for @newsengine/anal-probe.
export {
  probe, scan, summarize, ALL_CATEGORIES,
  type Finding, type Severity, type Category, type ScanOptions, type ProbeOptions, type ScanContext,
} from './probe.js';
export {
  securityChecks, secretChecks, exposureChecks, reliabilityChecks, seoChecks, a11yChecks, performanceChecks,
} from './checks.js';
export {
  scanSecrets, SECRET_RULES, type SecretRule, type SecretHit,
} from './core.js';
export {
  idorProbe, checkSecurityHeaders, checkCookieFlags,
  setTenantParam, classifyTenantAccess,
  type IdorCase, type IdorResult, type TenantAuth,
  type TenantProbeResponse, type TenantVerdict,
} from './testkit.js';
export {
  runNpmAudit, failsAtLevel, type AuditResult,
} from './audit.js';
export { lintCsp, type CspIssue } from './checks.js';
export {
  dnsChecks, gatherDns, evaluateDnsHygiene, apexOf,
  type DnsRecords,
} from './dns.js';
export { toSarif, type SarifOptions } from './sarif.js';
export {
  agentChecks, evaluateAgentReadiness, visibleText, aiCrawlersBlocked, AI_CRAWLERS,
  type AgentReadinessInput,
} from './agent.js';
export {
  findingKey, buildBaseline, applyBaseline,
  type Baseline, type BaselineDiff,
} from './baseline.js';
