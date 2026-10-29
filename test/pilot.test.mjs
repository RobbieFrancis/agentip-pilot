import test, { after } from 'node:test';
import pg from 'pg';
import { postgresAdapter } from '../lib/postgres.mjs';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { createPilot, ORIGIN } from '../lib/pilot.mjs';
import { signProof, canonical } from '../lib/pilot-crypto.mjs';
import { client } from '../lib/client.mjs';

function sqliteAdapter(database) {
  return {
    prepare(sql) { return { bind(...values) { const stmt = database.prepare(sql); return {
      async first() { return stmt.get(...values) ?? null; },
      async run() { const result = stmt.run(...values); return { meta: { changes: Number(result.changes) } }; },
      async all() { return { results: stmt.all(...values) }; },
      _execute() { const results = stmt.all(...values); return { results, meta: { changes: Number(database.prepare('SELECT changes() AS n').get().n) } }; },
    }; }, async first() { return database.prepare(sql).get() ?? null; }, async all() { return { results: database.prepare(sql).all() }; } }; },
    async batch(statements) {
      database.exec('BEGIN IMMEDIATE');
      try { const results = statements.map(statement => statement._execute()); database.exec('COMMIT'); return results; }
      catch (error) { database.exec('ROLLBACK'); throw error; }
    },
  };
}
async function key() {
  const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  return { publicKey: await crypto.subtle.exportKey('jwk', pair.publicKey).then(({ kty, crv, x }) => ({ kty, crv, x })), privateKey: pair.privateKey };
}
async function fixture() {
  let database, db;
  if (process.env.PILOT_TEST_DATABASE_URL) {
    const connectionString = process.env.PILOT_TEST_DATABASE_URL;
    if (!['127.0.0.1', 'localhost'].includes(new URL(connectionString).hostname)) throw new Error('Postgres tests require an isolated loopback test database');
    const admin = new pg.Pool({ connectionString, max: 1 });
    const schema = 'pilot_test_' + crypto.randomUUID().replaceAll('-', '');
    await admin.query('CREATE SCHEMA "' + schema + '"');
    const pool = new pg.Pool({ connectionString, options: '-c search_path=' + schema, max: 4 });
    for (const file of readdirSync(new URL('../netlify/database/migrations/', import.meta.url)).filter(x => x.endsWith('.sql')).sort()) await pool.query(readFileSync(new URL('../netlify/database/migrations/' + file, import.meta.url), 'utf8'));
    db = postgresAdapter(pool);
    after(async () => { await pool.end(); await admin.query('DROP SCHEMA "' + schema + '" CASCADE'); await admin.end(); });
  } else {
    database = new DatabaseSync(':memory:');
    for (const file of readdirSync(new URL('../drizzle/', import.meta.url)).filter(x => x.endsWith('.sql')).sort()) database.exec(readFileSync(new URL('../drizzle/' + file, import.meta.url), 'utf8'));
    db = sqliteAdapter(database);
    after(() => database.close());
  }
  let time = 1800000000;
  const api = createPilot({ db, now: () => time, pepper: 'test-pepper' });
  const call = async (path, value, extra = {}) => {
    const response = await api(new Request(ORIGIN + '/api/v1' + path, { method: value === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '192.0.2.10', ...extra }, body: value === undefined ? undefined : JSON.stringify(value) }));
    return { status: response.status, ...await response.json() };
  };
  const prove = async (input, identity, newIdentity) => {
    const result = await call('/challenges', input); assert.equal(result.status, 200, JSON.stringify(result));
    const proof = await signProof(identity.privateKey, identity.publicKey, result.challenge);
    const payload = newIdentity ? { proof, newKeyProof: await signProof(newIdentity.privateKey, newIdentity.publicKey, result.challenge) } : { proof };
    return { ...(await call('/proofs', payload)), payload, challenge: result.challenge };
  };
  const register = async name => {
    const primary = await key(), recovery = await key(), agentId = 'agt_' + crypto.randomUUID();
    const registration = await prove({ action: 'register', agentId, publicKey: primary.publicKey, recoveryPublicKey: recovery.publicKey, profile: { name, description: 'Operator-owned automated test identity' }, acceptPilotTerms: true }, primary);
    assert.equal(registration.status, 200, JSON.stringify(registration));
    return { primary, recovery, agentId, registration };
  };
  return { database, db, api, call, prove, register, setTime: value => time = value };
}

test('registration persists public records; authentication requires a fresh valid holder proof', async () => {
  const f = await fixture(), a = await f.register('Test agent');
  const record = await f.call('/agents/' + a.agentId); assert.equal(record.agent.verifiedIdentity, false);
  assert.equal(record.agent.assurance, 'key-possession-only');
  assert.ok(!JSON.stringify(record).includes('"d":'));
  const auth = await f.prove({ action: 'authenticate', agentId: a.agentId }, a.primary);
  assert.equal(auth.authenticated, true);
  assert.equal((await f.call('/proofs', auth.payload)).error, 'proof_replayed');
  const health = await f.call('/health'); assert.equal(health.registrations, 1); assert.equal(health.successfulAuthentications, 1);
});

test('an attacker key cannot spoof a registered primary or recovery key', async () => {
  const f = await fixture(), a = await f.register('Target'), attacker = await key();
  assert.equal((await f.prove({ action: 'authenticate', agentId: a.agentId }, attacker)).error, 'wrong_signing_key');
  assert.equal((await f.prove({ action: 'revoke', agentId: a.agentId, useRecovery: true }, attacker)).error, 'wrong_signing_key');
});

test('recovery rotates a stolen primary; old proofs and old key stop working', async () => {
  const f = await fixture(), a = await f.register('Rotate'), replacement = await key();
  const oldChallenge = await f.call('/challenges', { action: 'authenticate', agentId: a.agentId });
  const oldProof = await signProof(a.primary.privateKey, a.primary.publicKey, oldChallenge.challenge);
  const wrong = await f.prove({ action: 'rotate', agentId: a.agentId, newPublicKey: replacement.publicKey }, a.primary, replacement);
  assert.equal(wrong.error, 'wrong_signing_key');
  const rotation = await f.prove({ action: 'rotate', agentId: a.agentId, newPublicKey: replacement.publicKey }, a.recovery, replacement);
  assert.equal(rotation.status, 200);
  assert.equal((await f.call('/proofs', { proof: oldProof })).error, 'signing_key_changed');
  assert.equal((await f.prove({ action: 'authenticate', agentId: a.agentId }, a.primary)).error, 'wrong_signing_key');
  assert.equal((await f.prove({ action: 'authenticate', agentId: a.agentId }, replacement)).authenticated, true);
});

test('new primary must also prove possession during recovery rotation', async () => {
  const f = await fixture(), a = await f.register('Recovery'), replacement = await key(), wrong = await key();
  const result = await f.prove({ action: 'rotate', agentId: a.agentId, newPublicKey: replacement.publicKey }, a.recovery, wrong);
  assert.equal(result.error, 'wrong_signing_key');
});

test('recovery can revoke a stolen primary, including an already-issued auth challenge', async () => {
  const f = await fixture(), a = await f.register('Revoke');
  const pending = await f.call('/challenges', { action: 'authenticate', agentId: a.agentId });
  assert.equal((await f.prove({ action: 'authenticate', agentId: a.agentId }, a.primary)).authenticated, true, 'A stolen matching key remains usable before revocation');
  const revoked = await f.prove({ action: 'revoke', agentId: a.agentId, useRecovery: true }, a.recovery);
  assert.equal(revoked.status, 200); assert.equal(revoked.agent.profile.name, 'Revoked registration');
  const proof = await signProof(a.primary.privateKey, a.primary.publicKey, pending.challenge);
  assert.equal((await f.call('/proofs', { proof })).error, 'agent_revoked_or_expired');
});

test('one signed side is insufficient; reciprocal handshake requires the same stored context', async () => {
  const f = await fixture(), a = await f.register('Tenant'), b = await f.register('Landlord');
  const scope = { origin: 'https://rentals.example', resource: 'flat:42', action: 'negotiate' };
  const session = await f.call('/sessions', { initiatorId: a.agentId, peerId: b.agentId, scope });
  assert.equal(session.status, 'waiting_for_peer');
  const first = await f.prove({ action: 'handshake', agentId: a.agentId, sessionId: session.id }, a.primary);
  assert.equal(first.status, 'waiting_for_peer');
  const second = await f.prove({ action: 'handshake', agentId: b.agentId, sessionId: session.id }, b.primary);
  assert.equal(second.status, 'complete'); assert.equal(second.authorizesBusinessAction, false);
  assert.equal((await f.call('/challenges', { action: 'handshake', agentId: b.agentId, sessionId: session.id })).error, 'session_closed');
});

test('revocation invalidates completed sessions, and rotation invalidates old confirmations', async () => {
  const f = await fixture(), a = await f.register('A'), b = await f.register('B');
  const session = await f.call('/sessions', { initiatorId: a.agentId, peerId: b.agentId, scope: { origin: 'https://test.example', resource: 'example', action: 'test' } });
  await f.prove({ action: 'handshake', agentId: a.agentId, sessionId: session.id }, a.primary);
  const replacement = await key();
  await f.prove({ action: 'rotate', agentId: a.agentId, newPublicKey: replacement.publicKey }, a.recovery, replacement);
  const waiting = await f.prove({ action: 'handshake', agentId: b.agentId, sessionId: session.id }, b.primary);
  assert.equal(waiting.status, 'waiting_for_peer');
  const completed = await f.prove({ action: 'handshake', agentId: a.agentId, sessionId: session.id }, replacement);
  assert.equal(completed.status, 'complete');
  await f.prove({ action: 'revoke', agentId: b.agentId, useRecovery: false }, b.primary);
  assert.equal((await f.call('/sessions/' + session.id)).status, 'invalidated');
});

test('challenge expiry, field tampering, body limits, cross-origin requests and duplicate registration fail closed', async () => {
  const f = await fixture(), a = await f.register('Bound');
  const challenge = await f.call('/challenges', { action: 'authenticate', agentId: a.agentId });
  const tampered = { ...challenge.challenge, origin: 'https://attacker.example' };
  assert.equal((await f.call('/proofs', { proof: await signProof(a.primary.privateKey, a.primary.publicKey, tampered) })).error, 'challenge_binding_mismatch');
  f.setTime(1800000120);
  assert.equal((await f.call('/proofs', { proof: await signProof(a.primary.privateKey, a.primary.publicKey, challenge.challenge) })).error, 'challenge_expired');
  assert.equal((await f.call('/challenges', { action: 'authenticate', agentId: a.agentId }, { Origin: 'https://attacker.example' })).error, 'origin_not_allowed');
  assert.equal((await f.call('/proofs', { proof: 'x'.repeat(33000) })).status, 413);
  const duplicate = await f.call('/challenges', { action: 'register', agentId: 'agt_' + crypto.randomUUID(), publicKey: a.primary.publicKey, recoveryPublicKey: (await key()).publicKey, profile: { name: 'Duplicate', description: '' }, acceptPilotTerms: true });
  assert.equal(duplicate.error, 'key_already_registered');
});

test('simultaneously submitted proof is accepted only once', async () => {
  const f = await fixture(), a = await f.register('Replay race');
  const challenge = await f.call('/challenges', { action: 'authenticate', agentId: a.agentId });
  const proof = await signProof(a.primary.privateKey, a.primary.publicKey, challenge.challenge);
  const results = await Promise.all([f.call('/proofs', { proof }), f.call('/proofs', { proof })]);
  assert.equal(results.filter(x => x.authenticated).length, 1);
  assert.equal(results.filter(x => x.error === 'proof_replayed').length, 1);
});

test('challenge issuance is rate limited and registry survives handler recreation', async () => {
  const f = await fixture(), a = await f.register('Durable');
  for (let i = 0; i < 24; i++) assert.equal((await f.call('/challenges', { action: 'authenticate', agentId: a.agentId })).status, 200);
  assert.equal((await f.call('/challenges', { action: 'authenticate', agentId: a.agentId })).status, 429);
  const restarted = createPilot({ db: f.db, now: () => 1800000000, pepper: 'test-pepper' });
  const response = await restarted(new Request(ORIGIN + '/api/v1/agents/' + a.agentId));
  assert.equal((await response.json()).agent.id, a.agentId);
});

test('agent SDK authenticates and refuses altered origins before signing', async () => {
  const f = await fixture(), a = await f.register('SDK');
  const sdk = client(ORIGIN, (url, options) => f.api(new Request(url, options)));
  assert.equal((await sdk.prove({ action: 'authenticate', agentId: a.agentId }, a.primary)).authenticated, true);
  const corrupted = client(ORIGIN, async (url, options) => {
    const response = await f.api(new Request(url, options));
    const data = await response.json();
    if (data.challenge) data.challenge.origin = 'https://attacker.example';
    return new Response(JSON.stringify(data), { status: response.status });
  });
  await assert.rejects(corrupted.prove({ action: 'authenticate', agentId: a.agentId }, a.primary), /Unexpected challenge binding/);
});

test('SDK refuses a handshake without explicit review or with a different context', async () => {
  const f = await fixture(), a = await f.register('SDK A'), b = await f.register('SDK B');
  const session = await f.call('/sessions', { initiatorId: a.agentId, peerId: b.agentId, scope: { origin: 'https://test.example', resource: 'example', action: 'test' } });
  const sdk = client(ORIGIN, (url, options) => f.api(new Request(url, options)));
  const input = { action: 'handshake', agentId: a.agentId, sessionId: session.id };
  await assert.rejects(sdk.prove(input, a.primary), /review required/);
  await assert.rejects(sdk.prove(input, a.primary, undefined, () => false), /context refused/);
  assert.equal((await sdk.prove(input, a.primary, undefined, claims => claims.scope.action === 'test')).status, 'waiting_for_peer');
});

test('hosted proof parser rejects algorithm/type substitution and unexpected private fields', async () => {
  const f = await fixture(), a = await f.register('Strict');
  const c = await f.call('/challenges', { action: 'authenticate', agentId: a.agentId });
  const token = await signProof(a.primary.privateKey, a.primary.publicKey, c.challenge);
  const parts = token.split('.');
  for (const header of [{ alg: 'none', typ: 'agentip-pilot-proof+jwt' }, { alg: 'Ed25519', typ: 'another-protocol' }]) {
    const substituted = Buffer.from(JSON.stringify(header)).toString('base64url') + '.' + parts[1] + '.' + parts[2];
    assert.equal((await f.call('/proofs', { proof: substituted })).error, 'unsupported_header');
  }
  const privateField = await f.call('/challenges', { action: 'register', agentId: 'agt_' + crypto.randomUUID(), publicKey: { ...a.primary.publicKey, d: 'do-not-accept-private-key-material' }, recoveryPublicKey: (await key()).publicKey, profile: { name: 'Invalid', description: '' }, acceptPilotTerms: true });
  assert.equal(privateField.error, 'invalid_schema');
});

test('a still-valid challenge cannot complete an expired session', async () => {
  const f = await fixture(), a = await f.register('Expiry A'), b = await f.register('Expiry B');
  const session = await f.call('/sessions', { initiatorId: a.agentId, peerId: b.agentId, scope: { origin: 'https://test.example', resource: 'expiry', action: 'test' } });
  f.setTime(1800000299);
  const issued = await f.call('/challenges', { action: 'handshake', agentId: a.agentId, sessionId: session.id });
  f.setTime(1800000300);
  const result = await f.call('/proofs', { proof: await signProof(a.primary.privateKey, a.primary.publicKey, issued.challenge) });
  assert.equal(result.error, 'session_closed');
});

test('racing registrations of one key accept only one and roll back the losing challenge', async () => {
  const f = await fixture(), primary = await key(), recovery = await key();
  const challenges = await Promise.all([0, 1].map(i => f.call('/challenges', {
    action: 'register', agentId: 'agt_' + crypto.randomUUID(), publicKey: primary.publicKey,
    recoveryPublicKey: recovery.publicKey, profile: { name: 'Registration race ' + i, description: 'Synthetic test' }, acceptPilotTerms: true,
  })));
  for (const result of challenges) assert.equal(result.status, 200);
  const proofs = await Promise.all(challenges.map(async result => ({ proof: await signProof(primary.privateKey, primary.publicKey, result.challenge) })));
  const results = await Promise.all(proofs.map(proof => f.call('/proofs', proof)));
  assert.equal(results.filter(result => result.agent).length, 1);
  assert.equal(results.filter(result => result.error === 'key_already_registered').length, 1);
  const losing = results.findIndex(result => result.error === 'key_already_registered');
  assert.equal((await f.db.prepare('SELECT used_by FROM challenges WHERE id = ?').bind(challenges[losing].challenge.id).first()).used_by, null);
  assert.equal((await f.call('/health')).registrations, 1);
});

test('simultaneous reciprocal confirmations complete once both keys have signed', async () => {
  const f = await fixture(), a = await f.register('Concurrent A'), b = await f.register('Concurrent B');
  const session = await f.call('/sessions', { initiatorId: a.agentId, peerId: b.agentId, scope: { origin: 'https://test.example', resource: 'concurrent', action: 'test' } });
  const proofs = await Promise.all([a, b].map(async agent => {
    const issued = await f.call('/challenges', { action: 'handshake', agentId: agent.agentId, sessionId: session.id });
    assert.equal(issued.status, 200);
    return { proof: await signProof(agent.primary.privateKey, agent.primary.publicKey, issued.challenge) };
  }));
  const results = await Promise.all(proofs.map(proof => f.call('/proofs', proof)));
  assert.ok(results.every(result => ['waiting_for_peer', 'complete'].includes(result.status)));
  assert.equal((await f.call('/sessions/' + session.id)).status, 'complete');
});
