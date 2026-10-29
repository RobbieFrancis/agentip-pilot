import type { Config, Context } from '@netlify/functions';
import { getDatabase } from '@netlify/database';
import { createPilot } from '../../lib/pilot.mjs';
import { postgresAdapter } from '../../lib/postgres.mjs';

let database: ReturnType<typeof postgresAdapter> | undefined;
export default async (request: Request, context: Context) => {
  const origin = Netlify.env.get('PILOT_ORIGIN');
  const pepper = Netlify.env.get('RATE_LIMIT_PEPPER');
  let validOrigin = false;
  try {
    const parsed = new URL(origin ?? '');
    validOrigin = parsed.origin === origin && !parsed.username && !parsed.password &&
      (parsed.protocol === 'https:' || (process.env.NETLIFY_DEV === 'true' && ['127.0.0.1', 'localhost'].includes(parsed.hostname)));
  } catch { /* fail closed below */ }
  if (!validOrigin || !pepper) return Response.json({ error: 'pilot_not_configured' }, { status: 503, headers: { 'Cache-Control': 'no-store' } });
  try {
    database ??= postgresAdapter(getDatabase().pool);
    // Netlify supplies context.ip. Never trust caller-supplied Cloudflare/IP headers.
    const headers = new Headers(request.headers);
    headers.set('cf-connecting-ip', context.ip || 'unavailable');
    return await createPilot({ db: database, origin, pepper })(new Request(request, { headers }));
  } catch {
    console.error('Pilot runtime unavailable; request contents and credentials omitted');
    return Response.json({ error: 'pilot_unavailable' }, { status: 503, headers: { 'Cache-Control': 'no-store' } });
  }
};

export const config: Config = { path: '/api/v1/*' };
