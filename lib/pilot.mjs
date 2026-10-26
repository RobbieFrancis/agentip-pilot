import { b64, canonical, checkProof, ensure, exact, fingerprint, hash, PilotError, publicKey, readProofChallenge } from './pilot-crypto.mjs';
export const ORIGIN = 'https://reciprocal-agent-trust-pilot.robbie-francis.chatgpt.site';
const ACTIONS = ['register', 'authenticate', 'revoke', 'rotate', 'handshake'];
const RETENTION = 86400 * 30;
const id = prefix => prefix + '_' + crypto.randomUUID();
const validId = value => typeof value === 'string' && /^[a-z]+_[a-f0-9-]{36}$/.test(value);
function bounded(value, length, optional = false) { ensure(typeof value === 'string' && value.length <= length && (optional || value.trim().length > 0), 'invalid_text'); return value; }
function profile(value) {
  exact(value, ['name', 'description']);
  return { name: bounded(value.name, 64).trim(), description: bounded(value.description, 240, true).trim() };
}
function scope(value) {
  exact(value, ['origin', 'resource', 'action']);
  let url; try { url = new URL(value.origin); } catch { throw new PilotError(400, 'invalid_scope'); }
  ensure(url.protocol === 'https:' && url.origin === value.origin && !url.username && !url.password, 'invalid_scope');
  return { origin: value.origin, resource: bounded(value.resource, 128), action: bounded(value.action, 64) };
}
function view(row) {
  return { id: row.id, publicKey: JSON.parse(row.public_key), recoveryPublicKey: JSON.parse(row.recovery_key), profile: JSON.parse(row.profile), createdAt: row.created_at, expiresAt: row.expires_at, revokedAt: row.revoked_at, assurance: 'key-possession-only', verifiedIdentity: false };
}
async function active(db, agentId, now) {
  ensure(validId(agentId), 'invalid_agent_id');
  const agent = await db.prepare('SELECT * FROM agents WHERE id = ?').bind(agentId).first();
  ensure(agent, 'agent_not_found', 404);
  ensure(agent.revoked_at === null && agent.expires_at > now, 'agent_revoked_or_expired', 403);
  return agent;
}
async function limit(db, kind, network, now, max, window = 600) {
  const bucket = kind + ':' + network + ':' + Math.floor(now / window);
  const row = await db.prepare('INSERT INTO rate_limits(bucket, count, expires_at) VALUES(?, 1, ?) ON CONFLICT(bucket) DO UPDATE SET count = count + 1 RETURNING count').bind(bucket, now + window * 2).first();
  ensure(row.count <= max, 'rate_limited', 429);
}
async function body(request) {
  ensure(request.headers.get('content-type')?.split(';')[0] === 'application/json', 'json_required', 415);
  const reader = request.body?.getReader(); ensure(reader, 'body_required');
  let length = 0; const chunks = [];
  try {
    while (true) { const chunk = await reader.read(); if (chunk.done) break; length += chunk.value.length; ensure(length <= 32768, 'request_too_large', 413); chunks.push(chunk.value); }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  const bytes = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new PilotError(400, 'invalid_json'); }
}
async function makeChallenge(db, input, origin, now) {
  ensure(ACTIONS.includes(input.action), 'unknown_action');
  let agentId, signer, claims;
  if (input.action === 'register') {
    exact(input, ['action', 'agentId', 'publicKey', 'recoveryPublicKey', 'profile', 'acceptPilotTerms']);
    ensure(input.acceptPilotTerms === true, 'pilot_terms_required');
    ensure(validId(input.agentId) && input.agentId.startsWith('agt_'), 'invalid_agent_id');
    signer = publicKey(input.publicKey); const recovery = publicKey(input.recoveryPublicKey);
    ensure(canonical(signer) !== canonical(recovery), 'separate_recovery_key_required');
    ensure(!(await db.prepare('SELECT id FROM agents WHERE id = ? OR public_key = ? OR recovery_key = ?').bind(input.agentId, canonical(signer), canonical(recovery)).first()), 'key_already_registered', 409);
    const count = await db.prepare('SELECT count(*) AS count FROM agents').first(); ensure(count.count < 1000, 'pilot_capacity_reached', 503);
    agentId = input.agentId; claims = { publicKey: signer, recoveryPublicKey: recovery, profile: profile(input.profile), terms: 'pilot-v1' };
  } else {
    exact(input, input.action === 'rotate' ? ['action', 'agentId', 'newPublicKey'] : input.action === 'handshake' ? ['action', 'agentId', 'sessionId'] : input.action === 'revoke' ? ['action', 'agentId', 'useRecovery'] : ['action', 'agentId']);
    const agent = await active(db, input.agentId, now); agentId = agent.id;
    if (input.action === 'revoke') ensure(typeof input.useRecovery === 'boolean', 'invalid_schema');
    signer = JSON.parse(input.action === 'rotate' || (input.action === 'revoke' && input.useRecovery) ? agent.recovery_key : agent.public_key);
    claims = {};
    if (input.action === 'rotate') {
      const replacement = publicKey(input.newPublicKey);
      ensure(canonical(replacement) !== agent.public_key && canonical(replacement) !== agent.recovery_key, 'fresh_primary_key_required');
      ensure(!(await db.prepare('SELECT id FROM agents WHERE public_key = ?').bind(canonical(replacement)).first()), 'key_already_registered', 409);
      claims = { newPublicKey: replacement };
    }
    if (input.action === 'handshake') {
      ensure(validId(input.sessionId), 'invalid_session_id');
      const session = await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(input.sessionId).first();
      ensure(session && (session.a === agentId || session.b === agentId), 'session_not_found', 404);
      ensure(session.completed_at === null && session.expires_at > now, 'session_closed', 409);
      await active(db, session.a, now); await active(db, session.b, now);
      claims = { sessionId: session.id, participants: [session.a, session.b], scope: JSON.parse(session.scope) };
    }
  }
  const challenge = { kind: 'agentip-pilot-challenge', version: '0.2', id: id('chl'), nonce: b64(crypto.getRandomValues(new Uint8Array(32))), origin, action: input.action, agentId, signerFingerprint: await fingerprint(signer), claims, issuedAt: now, expiresAt: now + 120 };
  await db.prepare('INSERT INTO challenges(id, agent_id, payload, signer_key, expires_at) VALUES(?, ?, ?, ?, ?)').bind(challenge.id, agentId, canonical(challenge), canonical(signer), challenge.expiresAt).run();
  return challenge;
}
async function perform(db, input, now) {
  exact(input, input.newKeyProof === undefined ? ['proof'] : ['proof', 'newKeyProof']);
  const claimed = readProofChallenge(input.proof);
  ensure(claimed && validId(claimed.id), 'invalid_challenge');
  const stored = await db.prepare('SELECT * FROM challenges WHERE id = ?').bind(claimed.id).first();
  ensure(stored, 'unknown_challenge', 404); ensure(stored.used_by === null, 'proof_replayed', 409);
  const c = JSON.parse(stored.payload); const signer = JSON.parse(stored.signer_key);
  ensure(c.issuedAt <= now && c.expiresAt > now, 'challenge_expired', 401);
  await checkProof(input.proof, signer, c);
  if (c.action !== 'register') {
    const current = await active(db, c.agentId, now);
    const currentKey = c.action === 'rotate' || canonical(signer) === current.recovery_key ? current.recovery_key : current.public_key;
    ensure(canonical(signer) === currentKey, 'signing_key_changed', 401);
  }
  if (c.action === 'rotate') await checkProof(input.newKeyProof, c.claims.newPublicKey, c);
  else ensure(input.newKeyProof === undefined, 'unexpected_new_key_proof');
  let sessionKeys;
  if (c.action === 'handshake') {
    const session = await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(c.claims.sessionId).first();
    ensure(session && session.completed_at === null && session.expires_at > now, 'session_closed', 409);
    sessionKeys = [await active(db, session.a, now), await active(db, session.b, now)];
  }
  const attempt = id('op');
  const statements = [db.prepare('UPDATE challenges SET used_by = ? WHERE id = ? AND used_by IS NULL AND expires_at > ?').bind(attempt, c.id, now)];
  const guard = 'EXISTS(SELECT 1 FROM challenges WHERE id = ? AND used_by = ?)';
  if (c.action === 'register') {
    statements.push(db.prepare('INSERT INTO agents(id, public_key, recovery_key, profile, created_at, expires_at) SELECT ?, ?, ?, ?, ?, ? WHERE ' + guard + ' AND (SELECT count(*) FROM agents) < 1000').bind(c.agentId, canonical(c.claims.publicKey), canonical(c.claims.recoveryPublicKey), canonical(c.claims.profile), now, now + RETENTION, c.id, attempt));
  }
  if (c.action === 'authenticate') statements.push(db.prepare('UPDATE agents SET last_used_at = ? WHERE id = ? AND public_key = ? AND revoked_at IS NULL AND expires_at > ? AND ' + guard).bind(now, c.agentId, canonical(signer), now, c.id, attempt));
  if (c.action === 'revoke') statements.push(db.prepare('UPDATE agents SET revoked_at = ?, profile = ? WHERE id = ? AND (public_key = ? OR recovery_key = ?) AND revoked_at IS NULL AND ' + guard).bind(now, canonical({ name: 'Revoked registration', description: '' }), c.agentId, canonical(signer), canonical(signer), c.id, attempt));
  if (c.action === 'rotate') statements.push(db.prepare('UPDATE agents SET public_key = ?, last_used_at = ? WHERE id = ? AND recovery_key = ? AND revoked_at IS NULL AND expires_at > ? AND ' + guard).bind(canonical(c.claims.newPublicKey), now, c.agentId, canonical(signer), now, c.id, attempt));
  if (c.action === 'handshake') {
    statements.push(db.prepare('INSERT INTO confirmations(session_id, agent_id, key_fingerprint, at) SELECT ?, ?, ?, ? WHERE ' + guard + ' AND EXISTS(SELECT 1 FROM agents WHERE id = ? AND public_key = ? AND revoked_at IS NULL AND expires_at > ?) AND EXISTS(SELECT 1 FROM sessions WHERE id = ? AND completed_at IS NULL AND expires_at > ?) ON CONFLICT(session_id, agent_id) DO UPDATE SET key_fingerprint = excluded.key_fingerprint, at = excluded.at').bind(c.claims.sessionId, c.agentId, await fingerprint(signer), now, c.id, attempt, c.agentId, canonical(signer), now, c.claims.sessionId, now));
    statements.push(db.prepare('UPDATE sessions SET completed_at = ? WHERE id = ? AND completed_at IS NULL AND expires_at > ? AND ' + guard + ' AND EXISTS(SELECT 1 FROM agents a JOIN confirmations ca ON ca.agent_id = a.id WHERE a.id = sessions.a AND a.public_key = ? AND ca.session_id = sessions.id AND a.revoked_at IS NULL AND a.expires_at > ? AND ca.key_fingerprint = ?) AND EXISTS(SELECT 1 FROM agents b JOIN confirmations cb ON cb.agent_id = b.id WHERE b.id = sessions.b AND b.public_key = ? AND cb.session_id = sessions.id AND b.revoked_at IS NULL AND b.expires_at > ? AND cb.key_fingerprint = ?)').bind(now, c.claims.sessionId, now, c.id, attempt, sessionKeys[0].public_key, now, await fingerprint(JSON.parse(sessionKeys[0].public_key)), sessionKeys[1].public_key, now, await fingerprint(JSON.parse(sessionKeys[1].public_key))));
  }
  statements.push(db.prepare('INSERT INTO events(id, agent_id, action, at) SELECT ?, ?, ?, ? WHERE ' + guard).bind(attempt, c.agentId, c.action, now, c.id, attempt));
  let results;
  try { results = await db.batch(statements); }
  catch (error) { if (/UNIQUE constraint/.test(String(error))) throw new PilotError(409, 'key_already_registered'); throw error; }
  ensure(results[0].meta.changes === 1, 'proof_replayed', 409);
  ensure(results[1].meta.changes === 1, 'registration_changed_or_capacity', 409);
  if (c.action === 'handshake') return sessionView(db, c.claims.sessionId, now);
  return { action: c.action, authenticated: c.action === 'authenticate', agent: view(await db.prepare('SELECT * FROM agents WHERE id = ?').bind(c.agentId).first()), verifiedIdentity: false };
}
async function sessionView(db, sessionId, now) {
  const s = await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(sessionId).first(); ensure(s, 'session_not_found', 404);
  const a = await db.prepare('SELECT * FROM agents WHERE id = ?').bind(s.a).first();
  const b = await db.prepare('SELECT * FROM agents WHERE id = ?').bind(s.b).first();
  const confirmations = (await db.prepare('SELECT agent_id, key_fingerprint FROM confirmations WHERE session_id = ?').bind(s.id).all()).results;
  const current = a?.revoked_at === null && b?.revoked_at === null && a.expires_at > now && b.expires_at > now;
  // Recompute against current keys so rotation invalidates an earlier confirmation.
  const af = a ? await fingerprint(JSON.parse(a.public_key)) : '';
  const bf = b ? await fingerprint(JSON.parse(b.public_key)) : '';
  const valid = current && confirmations.some(c => c.agent_id === s.a && c.key_fingerprint === af) && confirmations.some(c => c.agent_id === s.b && c.key_fingerprint === bf);
  return { id: s.id, participants: [s.a, s.b], scope: JSON.parse(s.scope), expiresAt: s.expires_at, status: !current ? 'invalidated' : s.expires_at <= now ? 'expired' : s.completed_at !== null && valid ? 'complete' : 'waiting_for_peer', assurance: 'both-registered-keys-signed-this-context', verifiedIdentity: false, authorizesBusinessAction: false };
}
export function createPilot({ db, origin = ORIGIN, now = () => Math.floor(Date.now() / 1000), pepper = 'local-test-only' }) {
  return async request => {
    const time = now();
    const headers = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Access-Control-Allow-Origin': origin, 'Vary': 'Origin' };
    const send = (value, status = 200) => new Response(JSON.stringify(value), { status, headers });
    try {
      ensure(db, 'database_unavailable', 503);
      const path = new URL(request.url).pathname.replace(/^\/api\/v1/, '') || '/';
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...headers, 'Access-Control-Allow-Methods': 'GET, POST', 'Access-Control-Allow-Headers': 'Content-Type' } });
      if (request.method === 'GET' && path === '/health') {
        const counts = await db.prepare('SELECT count(*) AS registrations, sum(CASE WHEN revoked_at IS NULL AND expires_at > ? THEN 1 ELSE 0 END) AS active FROM agents').bind(time).first();
        const usage = await db.prepare("SELECT count(*) AS authentications FROM events WHERE action = 'authenticate'").first();
        return send({ status: 'ok', version: '0.2.0', assurance: 'key-possession-only', verifiedIdentity: false, registrations: counts.registrations, activeRegistrations: counts.active ?? 0, successfulAuthentications: usage.authentications, notice: 'Pilot counts include operator tests. Counts do not imply independent users or verified identities.' });
      }
      if (request.method === 'GET' && /^\/agents\/agt_[a-f0-9-]{36}$/.test(path)) {
        const agent = await db.prepare('SELECT * FROM agents WHERE id = ?').bind(path.split('/')[2]).first(); ensure(agent, 'agent_not_found', 404); return send({ agent: view(agent) });
      }
      if (request.method === 'GET' && /^\/sessions\/ses_[a-f0-9-]{36}$/.test(path)) return send(await sessionView(db, path.split('/')[2], time));
      ensure(request.method === 'POST', 'not_found', 404);
      ensure(!request.headers.get('origin') || request.headers.get('origin') === origin, 'origin_not_allowed', 403);
      ensure(request.headers.get('sec-fetch-site') !== 'cross-site', 'origin_not_allowed', 403);
      const network = await hash(pepper + ':' + Math.floor(time / 86400) + ':' + (request.headers.get('cf-connecting-ip') ?? 'local'));
      await limit(db, 'request', network, time, 90);
      const input = await body(request);
      if (path === '/challenges') {
        await limit(db, 'challenge', network, time, 25); await limit(db, 'global-challenge', 'all', time, 250);
        await db.batch([db.prepare('DELETE FROM challenges WHERE expires_at <= ?').bind(time), db.prepare('DELETE FROM rate_limits WHERE expires_at <= ?').bind(time), db.prepare('DELETE FROM events WHERE at < ?').bind(time - RETENTION), db.prepare('DELETE FROM confirmations WHERE session_id IN (SELECT id FROM sessions WHERE expires_at <= ?)').bind(time), db.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(time)]);
        return send({ challenge: await makeChallenge(db, input, origin, time), expiresIn: 120 });
      }
      if (path === '/proofs') return send(await perform(db, input, time));
      if (path === '/sessions') {
        exact(input, ['initiatorId', 'peerId', 'scope']); ensure(input.initiatorId !== input.peerId, 'distinct_agents_required');
        await active(db, input.initiatorId, time); await active(db, input.peerId, time);
        await limit(db, 'session', network, time, 10); await limit(db, 'global-session', 'all', time, 100);
        const context = scope(input.scope); const sessionId = id('ses');
        await db.prepare('INSERT INTO sessions(id, a, b, scope, expires_at) VALUES(?, ?, ?, ?, ?)').bind(sessionId, input.initiatorId, input.peerId, canonical(context), time + 300).run();
        return send(await sessionView(db, sessionId, time), 201);
      }
      throw new PilotError(404, 'not_found');
    } catch (error) {
      if (error instanceof PilotError) return send({ error: error.code }, error.status);
      console.error('Pilot operation failed without returning request contents');
      return send({ error: 'internal_error' }, 500);
    }
  };
}
