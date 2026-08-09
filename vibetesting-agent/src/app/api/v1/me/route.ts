import { resolveRequestUser } from '@/lib/auth';
import { getEntitlements } from '@/lib/entitlements';
import { json, errorResponse } from '@/lib/http';

export async function GET(req: Request) {
  try {
    const user = await resolveRequestUser(req);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    const entitlements = await getEntitlements(user);
    return json({
      id: user.id,
      email: user.email,
      name: user.name,
      image: user.image,
      githubLogin: user.githubLogin,
      plan: user.plan,
      planStatus: user.planStatus,
      entitlements,
    });
  } catch (err) {
    return errorResponse(err);
  }
}
