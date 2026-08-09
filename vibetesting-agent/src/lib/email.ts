import { config } from './config';

export async function sendEmail(
  to: string,
  subject: string,
  text: string,
  opts: { html?: string } = {},
): Promise<{ ok: boolean; id?: string; error?: string; devLogged?: boolean }> {
  if (!config.resendApiKey) {
    console.log('[email:dev]', { to, subject, text });
    return { ok: true, devLogged: true, id: 'dev' };
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${config.resendApiKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        from: config.emailFrom,
        to: [to],
        subject,
        text,
        html: opts.html,
      }),
    });
    const data = (await res.json().catch(() => ({}))) as { id?: string; message?: string };
    if (!res.ok) {
      console.error('[email] resend error', res.status, data);
      return { ok: false, error: data.message || `Email provider error ${res.status}` };
    }
    return { ok: true, id: data.id };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'Email send failed' };
  }
}
