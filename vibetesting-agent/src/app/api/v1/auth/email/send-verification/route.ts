/**
 * Send one-click inbox verification email (domain ownership path).
 */
import { resolveRequestUser, AuthError } from '@/lib/auth';
import { sendInboxVerification, isEmailInboxVerified } from '@/lib/ownership';
import { json, errorResponse } from '@/lib/http';
import { rateLimit } from '@/lib/rate-limit';
import { clientIp } from '@/lib/http';

export async function POST(req: Request) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) throw new AuthError();

    const ip = clientIp(req);
    const rl = await rateLimit(`email-verify:${user.id}:${ip}`, 5, 60 * 60 * 1000);
    if (!rl.ok) {
      return json({ error: 'Too many verification emails. Try again later.' }, 429);
    }

    if (isEmailInboxVerified(user)) {
      return json({
        ok: true,
        alreadyVerified: true,
        email: user.email,
        message: 'Inbox already verified.',
      });
    }

    const result = await sendInboxVerification(user);
    if (!result.sent) {
      return json(
        {
          error:
            'Could not send verification email. Ensure RESEND_API_KEY is configured, or contact support.',
        },
        502,
      );
    }

    return json({
      ok: true,
      email: user.email,
      message: `Check ${user.email} and click the verification link to prove you control that inbox.`,
      expiresAt: result.expiresAt.toISOString(),
      // Only present when Resend is not configured (dev)
      ...(result.devVerifyUrl ? { devVerifyUrl: result.devVerifyUrl } : {}),
    });
  } catch (err) {
    return errorResponse(err);
  }
}
