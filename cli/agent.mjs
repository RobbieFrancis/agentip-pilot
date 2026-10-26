#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { client, createKey, importIdentity } from '../lib/client.mjs';
import { canonical } from '../lib/pilot-crypto.mjs';
const command = process.argv[2]; const flags = new Map();
for (let index = 3; index < process.argv.length; index += 2) { if (!process.argv[index].startsWith('--') || !process.argv[index + 1]) throw new Error('Use --name value options'); flags.set(process.argv[index].slice(2), process.argv[index + 1]); }
const required = name => { const value = flags.get(name); if (!value) throw new Error('--' + name + ' is required'); return value; };
const server = flags.get('server') ?? 'https://reciprocal-agent-trust-pilot.robbie-francis.chatgpt.site';
const api = client(server);
const load = async path => JSON.parse(await readFile(path, 'utf8'));
async function save(path, data) { await mkdir(dirname(resolve(path)), { recursive: true, mode: 0o700 }); await writeFile(path, JSON.stringify(data, null, 2) + '\n', { flag: 'wx', mode: 0o600 }); }
async function storedKey(key) { return { publicKey: key.publicKey, privateJwk: await crypto.subtle.exportKey('jwk', key.privateKey) }; }
function recoveryIdentity(saved) {
  return crypto.subtle.importKey('jwk', saved.recoveryPrivateJwk, 'Ed25519', false, ['sign']).then(privateKey => ({ publicKey: Object.fromEntries(Object.entries(saved.recoveryPrivateJwk).filter(([key]) => ['kty', 'crv', 'x'].includes(key))), privateKey }));
}
try {
  let result;
  if (command === 'signup') {
    const identityPath = required('identity'), recoveryPath = required('recovery');
    if (resolve(identityPath) === resolve(recoveryPath)) throw new Error('Use separate primary and recovery files. Keep recovery offline.');
    if (flags.get('accept-pilot-terms') !== 'yes') throw new Error('Read /guide#terms, then pass --accept-pilot-terms yes');
    const agentId = 'agt_' + crypto.randomUUID(); const primary = await createKey(), recovery = await createKey();
    const profile = { name: required('name').trim(), description: (flags.get('description') ?? 'Independent agent testing the experimental pilot').trim() };
    await save(recoveryPath, { format: 'agentip-pilot-recovery-v1', server, agentId, recoveryPrivateJwk: await crypto.subtle.exportKey('jwk', recovery.privateKey) });
    await save(identityPath, { format: 'agentip-pilot-primary-v1', server, agentId, profile, recoveryPublicKey: recovery.publicKey, ...await storedKey(primary) });
    result = await api.prove({ action: 'register', agentId, publicKey: primary.publicKey, recoveryPublicKey: recovery.publicKey, profile, acceptPilotTerms: true }, primary);
    result = { ...result, primaryKeySavedTo: resolve(identityPath), recoveryKeySavedTo: resolve(recoveryPath), instruction: 'Move recovery offline and separate from the primary signing environment.' };
  } else if (command === 'resume') {
    const saved = await load(required('identity'));
    if (flags.get('accept-pilot-terms') !== 'yes') throw new Error('Pass --accept-pilot-terms yes to resume enrollment');
    const existing = await api.call('/agents/' + saved.agentId).catch(() => null);
    if (existing) {
      if (canonical(existing.agent.publicKey) !== canonical(saved.publicKey) || existing.agent.revokedAt !== null) throw new Error('Registration has changed or was revoked');
      result = { ...existing, reconciled: true };
    } else {
      if (!saved.profile || !saved.recoveryPublicKey) throw new Error('Saved registration metadata is missing');
      result = await api.prove({ action: 'register', agentId: saved.agentId, publicKey: saved.publicKey, recoveryPublicKey: saved.recoveryPublicKey, profile: saved.profile, acceptPilotTerms: true }, await importIdentity(saved));
    }
  } else if (command === 'authenticate') {
    const saved = await load(required('identity')); result = await api.prove({ action: 'authenticate', agentId: saved.agentId }, await importIdentity(saved));
  } else if (command === 'revoke') {
    const recoveryPath = flags.get('recovery'); const saved = await load(recoveryPath ?? required('identity'));
    result = await api.prove({ action: 'revoke', agentId: saved.agentId, useRecovery: !!recoveryPath }, recoveryPath ? await recoveryIdentity(saved) : await importIdentity(saved));
  } else if (command === 'rotate') {
    const saved = await load(required('recovery')); const replacementPath = required('replacement'); const replacement = await createKey();
    await save(replacementPath, { format: 'agentip-pilot-primary-v1', server, agentId: saved.agentId, ...await storedKey(replacement) });
    result = await api.prove({ action: 'rotate', agentId: saved.agentId, newPublicKey: replacement.publicKey }, await recoveryIdentity(saved), replacement);
    result = { ...result, replacementIdentityPath: resolve(replacementPath) };
  } else if (command === 'session') {
    const saved = await load(required('identity'));
    result = await api.call('/sessions', { initiatorId: saved.agentId, peerId: required('peer'), scope: { origin: required('origin'), resource: required('resource'), action: required('action') } });
  } else if (command === 'handshake') {
    const saved = await load(required('identity'));
    const expected = { origin: required('origin'), resource: required('resource'), action: required('action') }, peer = required('peer');
    result = await api.prove({ action: 'handshake', agentId: saved.agentId, sessionId: required('session') }, await importIdentity(saved), undefined, claims => {
      return claims.participants.length === 2 && claims.participants.includes(saved.agentId) && claims.participants.includes(peer) && ['origin', 'resource', 'action'].every(key => claims.scope[key] === expected[key]);
    });
  } else if (command === 'status') result = await api.call('/health');
  else throw new Error('Commands: signup, resume, authenticate, session, handshake, rotate, revoke, status. See README.md.');
  console.log(JSON.stringify(result, null, 2));
} catch (error) { console.error(error.message); process.exitCode = 1; }
