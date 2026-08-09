import { CreateProjectForm } from '@/components/forms';

export default function NewProjectPage() {
  return (
    <div className="space-y-4">
      <h1 className="mono text-2xl font-bold">New project</h1>
      <p className="text-sm text-[var(--mut)]">
        Add the production URL you ship to. Verify DNS ownership, then enable deploy webhooks for every
        software update.
      </p>
      <CreateProjectForm />
    </div>
  );
}
