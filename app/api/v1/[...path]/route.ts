import { env } from 'cloudflare:workers';
import { createPilot, ORIGIN } from '../../../../lib/pilot.mjs';
export const dynamic = 'force-dynamic';
async function handle(request: Request) {
  const settings = env as Cloudflare.Env & { RATE_LIMIT_PEPPER?: string };
  if (!settings.RATE_LIMIT_PEPPER) return Response.json({ error: 'pilot_not_configured' }, { status: 503 });
  const origin = process.env.NODE_ENV === 'development' ? new URL(request.url).origin : ORIGIN;
  return createPilot({ db: settings.DB, pepper: settings.RATE_LIMIT_PEPPER, origin })(request);
}
export const GET = handle;
export const POST = handle;
export const OPTIONS = handle;
