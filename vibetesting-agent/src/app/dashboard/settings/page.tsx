import { getSessionUser } from '@/lib/auth';
import { SettingsForm } from '@/components/forms';

export default async function SettingsPage() {
  const user = await getSessionUser();
  if (!user) return null;
  return (
    <div className="space-y-6">
      <h1 className="mono text-2xl font-bold">Settings</h1>
      <SettingsForm notifyEmail={user.notifyEmail} slackWebhookUrl={user.slackWebhookUrl} />
    </div>
  );
}
