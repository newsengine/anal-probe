import Link from 'next/link';
import { publicConfig } from '@/lib/config';

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const sp = await searchParams;
  const pub = publicConfig();

  return (
    <div className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6">
      <Link href="/" className="mono mb-8 font-extrabold text-[var(--lime)]">
        ← VibeTesting Agent
      </Link>
      <div className="panel p-8">
        <h1 className="mono text-2xl font-bold">Sign in</h1>
        <p className="mt-2 text-sm text-[var(--mut)]">
          Hosted scans require an account. Full scans only run after you prove ownership: sign in with an
          email on the domain you are testing and click the inbox verify link, or place a DNS TXT record.
        </p>
        {sp.error && (
          <p className="mt-4 rounded-lg border border-[var(--hi)]/40 bg-[var(--hi)]/10 px-3 py-2 text-sm text-[var(--hi)]">
            Auth error: {sp.error}
          </p>
        )}
        <div className="mt-6 space-y-3">
          {pub.workosEnabled ? (
            <a href="/api/auth/workos" className="btn-primary w-full">
              Continue with WorkOS
            </a>
          ) : (
            <a href="/api/auth/github" className="btn-primary w-full">
              Continue with GitHub
            </a>
          )}
          {!pub.workosEnabled && (
            <p className="text-xs text-[var(--mut)]">
              WorkOS not configured — using GitHub OAuth / dev login. Set{' '}
              <code className="text-[var(--ink)]">WORKOS_API_KEY</code> +{' '}
              <code className="text-[var(--ink)]">WORKOS_CLIENT_ID</code>.
            </p>
          )}
        </div>
        <p className="mt-6 text-xs text-[var(--mut)]">
          By continuing you agree to{' '}
          <Link href="/legal/acceptable-use" className="text-[var(--lime)]">
            acceptable use
          </Link>{' '}
          — only scan systems you own or may test.
        </p>
      </div>
    </div>
  );
}
