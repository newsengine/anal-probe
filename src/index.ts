// Public API for @newsengine/saas-security-kit.
export { probe, summarize, type Finding, type Severity, type ProbeOptions } from './probe.js';
export {
  idorProbe, checkSecurityHeaders, checkCookieFlags,
  type IdorCase, type IdorResult, type TenantAuth,
} from './testkit.js';
