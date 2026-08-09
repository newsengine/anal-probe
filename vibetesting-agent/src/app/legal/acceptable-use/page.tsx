import Link from 'next/link';

export default function AupPage() {
  return (
    <div className="mx-auto max-w-2xl px-6 py-16">
      <Link href="/" className="mono text-[var(--lime)]">
        ← VibeTesting Agent
      </Link>
      <h1 className="mono mt-6 text-3xl font-bold">Acceptable Use</h1>
      <div className="mt-6 space-y-4 text-sm leading-relaxed text-[var(--mut)]">
        <p>Last updated: 2026-07-10</p>
        <ul className="list-disc space-y-2 pl-5">
          <li>Only scan systems you own or have written authorization to test.</li>
          <li>Confirm the authorization checkbox (or API <code>authorized: true</code>) truthfully.</li>
          <li>Do not use VibeTesting Agent for surveillance, harassment, or unauthorized access attempts.</li>
          <li>Do not attempt to bypass rate limits, quotas, or domain verification.</li>
          <li>Do not run recon/active modes against third-party infrastructure via our cloud.</li>
          <li>Report product vulnerabilities to the maintainers; do not exploit VibeTesting Agent itself.</li>
        </ul>
        <p>Violations may result in immediate suspension without refund.</p>
      </div>
    </div>
  );
}
