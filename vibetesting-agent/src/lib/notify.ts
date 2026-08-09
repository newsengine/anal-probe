import { config } from './config';
import { sendEmail } from './email';
import type { User } from './db/schema';

export async function notifyScanComplete(
  user: User,
  payload: {
    scanId: string;
    url: string;
    score: number;
    grade: string;
    summary: { failHigh: number; failMedium: number; failed: number };
    newHighs: number;
    projectName?: string;
  },
): Promise<void> {
  const title = payload.projectName
    ? `VibeTesting Agent: ${payload.projectName} → ${payload.grade} (${payload.score})`
    : `VibeTesting Agent: ${payload.url} → ${payload.grade} (${payload.score})`;
  const body = [
    title,
    `URL: ${payload.url}`,
    `Score: ${payload.score}/100 (${payload.grade})`,
    `Failures: ${payload.summary.failed} (high ${payload.summary.failHigh}, medium ${payload.summary.failMedium})`,
    payload.newHighs ? `⚠️ ${payload.newHighs} new high-severity finding(s) vs baseline` : 'No new highs vs baseline',
    `Report: ${config.appUrl}/dashboard/scans/${payload.scanId}`,
  ].join('\n');

  if (user.slackWebhookUrl) {
    try {
      await fetch(user.slackWebhookUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          text: body,
          blocks: [
            {
              type: 'section',
              text: { type: 'mrkdwn', text: `*${title}*\n${body.replace(title + '\n', '')}` },
            },
          ],
        }),
      });
    } catch {
      /* ignore slack errors */
    }
  }

  if (user.notifyEmail && (payload.newHighs > 0 || payload.summary.failHigh > 0)) {
    await sendEmail(user.email, title, body);
  }
}
