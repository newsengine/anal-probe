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
  type IdorCase, type IdorResult, type TenantAuth,
} from './testkit.js';
export {
  runNpmAudit, failsAtLevel, type AuditResult,
} from './audit.js';
