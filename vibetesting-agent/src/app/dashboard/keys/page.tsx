import { getSessionUser } from '@/lib/auth';
import { listApiKeys } from '@/lib/api-keys';
import { CreateKeyForm } from '@/components/forms';

export default async function KeysPage() {
  const user = await getSessionUser();
  if (!user) return null;
  const keys = await listApiKeys(user.id);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="mono text-2xl font-bold">API keys</h1>
        <p className="mt-1 text-sm text-[var(--mut)]">
          Use with MCP, CI, and <code className="text-[var(--ink)]">Authorization: Bearer sk_live_…</code>
        </p>
      </div>
      <CreateKeyForm />
      <div className="space-y-2">
        {keys.map((k) => (
          <div key={k.id} className="panel flex items-center justify-between p-4 text-sm">
            <div>
              <div className="font-semibold">{k.name}</div>
              <div className="mono text-xs text-[var(--mut)]">{k.keyPrefix}</div>
            </div>
            <form action={`/api/v1/keys/${k.id}`} method="POST">
              {/* DELETE via client would be better; use fetch revoke button in form component if needed */}
              <span className="text-xs text-[var(--mut)]">
                created {k.createdAt?.toISOString?.()?.slice(0, 10)}
              </span>
            </form>
          </div>
        ))}
        {keys.length === 0 && <p className="text-[var(--mut)]">No keys yet.</p>}
      </div>
    </div>
  );
}
