/**
 * Inventory of check IDs that must have true-positive / true-negative coverage
 * via the known-bad / known-good fixtures.
 *
 * These are stable finding IDs the engine emits — not marketing categories.
 * Dynamic IDs (cookie.<name>, component per-lib) are covered separately.
 */

/** Must FAIL (pass === false) when probing the known-bad fixture. */
export const MUST_FAIL_ON_BAD: readonly string[] = [
  // security — open / missing headers
  'tls.scheme',
  'header.strict-transport-security',
  'header.x-content-type-options',
  'header.referrer-policy',
  'header.x-frame-options',
  'header.content-security-policy',
  'header.permissions-policy',
  'securitytxt',
  'sri',
  'open-redirect',
  // secrets
  'secret.stripe.sk_live',
  'secret.aws.akid',
  // exposure (path is encoded into id as exposed<path>)
  'exposed/.env',
  'exposed/.git/config',
  'exposed/.git/HEAD',
  'exposed/wrangler.toml',
  'exposed/package.json',
  'exposed/backup.sql',
  'exposed/.aws/credentials',
  'exposed/config.json',
  'exposed/actuator/health',
  'exposed/metrics',
  'exposed/swagger.json',
  // seo / a11y basics on leaky html
  // (optional — leaky html has empty title / no lang)
];

/** Must PASS or be absent-as-fail when probing known-good (headers + no leaks). */
export const MUST_PASS_OR_ABSENT_FAIL_ON_GOOD: readonly string[] = [
  'header.strict-transport-security',
  'header.x-content-type-options',
  'header.referrer-policy',
  'header.x-frame-options',
  'header.content-security-policy',
  'header.permissions-policy',
  'securitytxt',
  'secret.none', // emitted when no secrets found
];

/** Must NOT appear as fail on known-good (true negatives). */
export const MUST_NOT_FAIL_ON_GOOD: readonly string[] = [
  'header.strict-transport-security',
  'header.x-content-type-options',
  'header.referrer-policy',
  'header.x-frame-options',
  'header.content-security-policy',
  'header.permissions-policy',
  'securitytxt',
  'secret.stripe.sk_live',
  'secret.aws.akid',
  'exposed/.env',
  'exposed/.git/config',
  'exposed/.git/HEAD',
  'exposed/wrangler.toml',
  'exposed/package.json',
  'exposed/backup.sql',
  'exposed/.aws/credentials',
  'exposed/config.json',
  'open-redirect',
  'sri',
];

/** Secret rule IDs from SECRET_RULES — unit-tested with crafted strings. */
export const SECRET_RULE_IDS: readonly string[] = [
  'aws.akid',
  'stripe.sk_live',
  'stripe.rk_live',
  'privatekey',
  'github.pat',
  'github.pat_fine',
  'slack.token',
  'anthropic.key',
  'openai.key',
  'google.apikey',
  'sendgrid.key',
  'twilio.sk',
  'supabase.service_role',
];

/** Representative samples that should hit each secret rule (unit level). */
export const SECRET_SAMPLES: Record<string, string> = {
  'aws.akid': 'AKIAIOSFODNN7EXAMPLE',
  'stripe.sk_live': ['sk', 'live', '51' + 'x'.repeat(28)].join('_'),
  'stripe.rk_live': ['rk', 'live', '51' + 'y'.repeat(28)].join('_'),
  privatekey: '-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----',
  'github.pat': `ghp_${'a'.repeat(36)}`,
  'github.pat_fine': `github_pat_${'A'.repeat(60)}`,
  'slack.token': 'xoxb-1234567890-abcdefghij',
  'anthropic.key': 'sk-ant-api03-abcdefghijklmnopqrst',
  'openai.key': `sk-proj-${'a'.repeat(20)}${'b'.repeat(15)}`,
  'google.apikey': `AIza${'A'.repeat(35)}`,
  'sendgrid.key': `SG.${'A'.repeat(22)}.${'B'.repeat(43)}`,
  'twilio.sk': `SK${'0'.repeat(32)}`,
  // service_role JWT — payload role=service_role
  'supabase.service_role': (() => {
    const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const p = Buffer.from(JSON.stringify({ role: 'service_role', ref: 'x' })).toString('base64url');
    return `${h}.${p}.signaturepartxx`;
  })(),
};

/** Clean strings that must NOT match secret rules (false-positive guards). */
export const SECRET_NEGATIVES: readonly string[] = [
  'pk_live_public_stripe_key_ok_to_ship',
  'sk_test_not_live_mode_key_should_not_match_live_rule_only',
  'const apiKey = process.env.STRIPE_SECRET_KEY',
  'https://example.com/path?token=public',
  'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig', // anon role JWT
];
