'use client';
import { useEffect, useState } from 'react';
import { signProof, canonical } from '../lib/pilot-crypto.mjs';
type Key = { publicKey: { kty: string; crv: string; x: string }; privateKey: CryptoKey };
type LocalIdentity = { agentId: string; primary: Key; recoveryPublicKey: Key['publicKey']; registered: boolean; profile: { name: string; description: string } };
async function localIdentity(value?: LocalIdentity): Promise<LocalIdentity | undefined> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const open = indexedDB.open('reciprocal-agent-trust-pilot', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('identity');
    open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error);
  });
  return new Promise((resolve, reject) => {
    const tx = database.transaction('identity', value ? 'readwrite' : 'readonly');
    const request = value ? tx.objectStore('identity').put(value, 'current') : tx.objectStore('identity').get('current');
    let result: LocalIdentity | undefined;
    request.onsuccess = () => { result = value ?? request.result; };
    tx.oncomplete = () => { database.close(); resolve(result); }; tx.onerror = () => { database.close(); reject(tx.error); };
  });
}
async function makeKey(extractable: boolean): Promise<Key> {
  const pair = await crypto.subtle.generateKey('Ed25519', extractable, ['sign', 'verify']) as CryptoKeyPair;
  const { kty, crv, x } = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { publicKey: { kty: kty!, crv: crv!, x: x! }, privateKey: pair.privateKey };
}
async function api(path: string, input?: unknown): Promise<any> {
  const response = await fetch('/api/v1' + path, input === undefined ? undefined : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) });
  const data: any = await response.json(); if (!response.ok) throw new Error(data.error ?? 'Request failed'); return data;
}
export default function PilotClient() {
  const [identity, setIdentity] = useState<LocalIdentity>(); const [name, setName] = useState(''); const [description, setDescription] = useState('');
  const [saved, setSaved] = useState(false); const [terms, setTerms] = useState(false); const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('Ready to try it. Use a separate testing identity.'); const [evidence, setEvidence] = useState<unknown>();
  const [peer, setPeer] = useState(''); const [session, setSession] = useState(''); const [resource, setResource] = useState('demo:flat-42');
  const [health, setHealth] = useState<{ registrations: number; successfulAuthentications: number }>();
  useEffect(() => { localIdentity().then(value => { if (value) { setIdentity(value); setName(value.profile.name); setDescription(value.profile.description); } }).catch(() => setMessage('Device storage is unavailable. Use the agent CLI instead.')); api('/health').then(setHealth).catch(() => {}); }, []);
  async function action(task: () => Promise<void>) { setBusy(true); try { await task(); } catch (error) { setMessage(error instanceof Error ? error.message : 'Operation failed'); } finally { setBusy(false); } }
  async function prepare() {
    if (!name.trim()) throw new Error('Give this testing agent a name.');
    const primary = await makeKey(false), recovery = await makeKey(true);
    const record: LocalIdentity = { agentId: 'agt_' + crypto.randomUUID(), primary, recoveryPublicKey: recovery.publicKey, registered: false, profile: { name: name.trim(), description: description.trim() } };
    const backup = { format: 'agentip-pilot-recovery-v1', server: window.location.origin, agentId: record.agentId, recoveryPrivateJwk: await crypto.subtle.exportKey('jwk', recovery.privateKey), warning: 'Keep offline and separate from your primary signing device. Anyone with this file can revoke or replace the primary key.' };
    const url = URL.createObjectURL(new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = record.agentId + '-RECOVERY-KEEP-OFFLINE.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    await localIdentity(record); setIdentity(record); setSaved(false); setMessage('Save the recovery download somewhere separate, then confirm below. The primary key stays in this browser.');
  }
  async function prove(input: Record<string, unknown>, local = identity) {
    if (!local) throw new Error('Create a testing identity first.');
    const { challenge } = await api('/challenges', input);
    if (challenge.origin !== window.location.origin || challenge.agentId !== local.agentId || challenge.action !== input.action) throw new Error('Unexpected challenge context');
    if (input.action === 'register' && (canonical(challenge.claims.publicKey) !== canonical(local.primary.publicKey) || canonical(challenge.claims.recoveryPublicKey) !== canonical(local.recoveryPublicKey) || canonical(challenge.claims.profile) !== canonical(local.profile))) throw new Error('Registration claims mismatch');
    return api('/proofs', { proof: await signProof(local.primary.privateKey, local.primary.publicKey, challenge) });
  }
  async function register() {
    if (!identity || !saved || !terms) throw new Error('Save your recovery file and accept the pilot terms first.');
    let result;
    try { result = await prove({ action: 'register', agentId: identity.agentId, publicKey: identity.primary.publicKey, recoveryPublicKey: identity.recoveryPublicKey, profile: identity.profile, acceptPilotTerms: true }); }
    catch (error) {
      const existing = await api('/agents/' + identity.agentId).catch(() => null);
      if (!existing || canonical(existing.agent.publicKey) !== canonical(identity.primary.publicKey) || existing.agent.revokedAt !== null) throw error;
      result = existing;
    }
    const registered = { ...identity, registered: true }; await localIdentity(registered); setIdentity(registered); setEvidence(result); setMessage('Your agent key is registered. Its operator identity has not been verified.'); api('/health').then(setHealth).catch(() => {});
  }
  return <><header className="shell"><a className="brand" href="/">⇄ <span>Reciprocal</span><small>AGENT TRUST PILOT</small></a><nav><a href="#join">Register a key</a><a href="/guide">Agent guide ↗</a><a href="https://github.com/RobbieFrancis/agentip-pilot">Source ↗</a></nav></header>
    <main><section className="hero shell"><p className="eyebrow"><span className="live-dot"/>OPEN EXPERIMENT · AGENTIP NAME IS PROVISIONAL</p><h1>Show your key.<br/><em>Ask for theirs.</em></h1><p className="intro">A small, open pilot for agents to register a key,<br/>prove control, and check the other side.</p><div className="hero-row"><a className="button" href="#join">Try a real registration ↓</a><span>No email. No payment. Your private key stays with you.</span></div><div className="boundary"><strong>Key possession ≠ verified identity.</strong><span>This pilot does not verify people, property ownership, or business authority. A stolen signing key can impersonate its owner until recovery or revocation.</span></div></section>
    <section className="shell story"><p className="eyebrow">A HANDSHAKE HAS TWO SIDES</p><div><h2>Your agent should<br/>check the landlord too.</h2><p>Two agents sign a fresh challenge for the same resource and action. A session completes only when both registered keys have signed. Either party can inspect the context and refuse.</p><p>Start with testing identities. Passing a handshake does not authorize a lease, payment, or other business action.</p></div></section>
    <section className="join-band" id="join"><div className="shell"><div className="section-top"><div><p className="eyebrow">REGISTER · AUTHENTICATE · RECOVER</p><h2>Give your testing agent<br/>a key of its own.</h2></div><div className="counts"><strong>{health?.registrations ?? '—'}</strong><span>pilot registrations, including operator tests</span><strong>{health?.successfulAuthentications ?? '—'}</strong><span>successful authentication checks</span></div></div><div className="workspace"><section className="panel"><span className="step">01 / YOUR DEVICE</span><h3>{identity?.registered ? 'Registered on this device' : 'Create a browser test agent'}</h3>{identity?.registered ? <><p className="badge">Key registered · identity unverified</p><label>Your agent ID</label><code className="identifier">{identity.agentId}</code><p className="small">The signing key is stored by this browser as a non-exportable key. Compromised browser software can still misuse it.</p><button disabled={busy} onClick={() => action(async () => { const result = await prove({ action: 'authenticate', agentId: identity.agentId }); setEvidence(result); setMessage('Fresh proof accepted. This device can use the registered signing key.'); })}>Prove key possession</button><button className="secondary" disabled={busy} onClick={() => action(async () => { const result = await prove({ action: 'revoke', agentId: identity.agentId, useRecovery: false }); setEvidence(result); setMessage('Registration revoked. This key will no longer authenticate. Use the CLI and offline recovery file for key replacement.'); })}>Revoke this registration</button><p className="small">Revocation is permanent. Key replacement uses the separate recovery file and the <a href="/guide#recovery">CLI recovery flow</a>.</p></> : <><label htmlFor="agent-name">Testing agent name</label><input id="agent-name" value={name} maxLength={64} onChange={event => setName(event.target.value)} disabled={!!identity}/><label htmlFor="agent-description">What will it test? <span>(optional)</span></label><textarea id="agent-description" value={description} maxLength={240} onChange={event => setDescription(event.target.value)} disabled={!!identity}/>{!identity ? <button disabled={busy || !name.trim()} onClick={() => action(prepare)}>Create keys & download recovery file</button> : <><p className="small">Keys prepared for <strong>{identity.profile.name}</strong>. Recovery private keys are not stored in the service or this browser’s key database.</p><label className="check"><input type="checkbox" checked={saved} onChange={event => setSaved(event.target.checked)}/>I saved the recovery file separately from this device.</label><label className="check"><input type="checkbox" checked={terms} onChange={event => setTerms(event.target.checked)}/>I accept the <a href="/guide#terms">pilot terms and data notice</a> and will use a testing identity.</label><button disabled={busy || !saved || !terms} onClick={() => action(register)}>Register this agent key</button></>}</>}</section>
    <section className="panel"><span className="step">02 / THE OTHER SIDE</span><h3>Complete a mutual handshake</h3><p className="small">Share IDs through a channel you trust. Both sides must review and sign the same session. Resource names are claims; the service does not verify ownership.</p><label htmlFor="peer">Other agent’s registration ID</label><input id="peer" value={peer} onChange={event => setPeer(event.target.value)} placeholder="agt_…"/><label htmlFor="resource">Resource to discuss</label><input id="resource" value={resource} maxLength={128} onChange={event => setResource(event.target.value)}/><button disabled={busy || !identity?.registered || !peer} onClick={() => action(async () => { const result = await api('/sessions', { initiatorId: identity!.agentId, peerId: peer.trim(), scope: { origin: 'https://rentals.example', resource, action: 'demo.negotiate' } }); setSession(result.id); setEvidence(result); setMessage('Testing session created. Share its ID with the other agent.'); })}>Create a testing session</button><label htmlFor="session">Session ID to review and sign</label><input id="session" value={session} onChange={event => setSession(event.target.value)} placeholder="ses_…"/><button className="secondary" disabled={busy || !session} onClick={() => action(async () => { const result = await api('/sessions/' + session.trim()); setEvidence(result); setMessage('Review the participants, origin, resource and action below before signing.'); })}>Review session context</button><button disabled={busy || !identity?.registered || !session} onClick={() => action(async () => {
      const { challenge } = await api('/challenges', { action: 'handshake', agentId: identity!.agentId, sessionId: session.trim() });
      if (challenge.origin !== window.location.origin || challenge.action !== 'handshake' || challenge.agentId !== identity!.agentId || challenge.claims.sessionId !== session.trim()) throw new Error('Unexpected challenge context');
      const context = challenge.claims.scope;
      if (!window.confirm('Sign a TEST handshake?\nParticipants: ' + challenge.claims.participants.join(' ↔ ') + '\nOrigin: ' + context.origin + '\nResource: ' + context.resource + '\nAction: ' + context.action + '\nThis does not verify identity or authorize a business action.')) return;
      const result = await api('/proofs', { proof: await signProof(identity!.primary.privateKey, identity!.primary.publicKey, challenge) }); setEvidence(result); setMessage(result.status === 'complete' ? 'Both registered keys signed the context. Identity and authority remain unverified.' : 'Your proof was accepted. Waiting for the other agent.');
    })}>Review & sign this session</button></section></div><div className="feedback" role="status" aria-live="polite">{busy ? 'Checking…' : message}</div>{evidence !== undefined && <details className="evidence" open><summary>Inspect the actual response</summary><pre>{JSON.stringify(evidence, null, 2)}</pre></details>}</div></section>
    <section className="shell integration"><div><p className="eyebrow">FOR AGENT DEVELOPERS</p><h2>A real API.<br/>A small trust claim.</h2><p>Register a separate test key, authenticate, and join a reciprocal session from your own agent. Keep the recovery key offline. No AI-provider key is required.</p><a href="/guide">Read the complete quickstart ↗</a></div><pre><code>{`GET  /api/v1/health\nPOST /api/v1/challenges\nPOST /api/v1/proofs\nPOST /api/v1/sessions\nGET  /api/v1/agents/{id}\nGET  /api/v1/sessions/{id}\n\nAssurance: key possession only\nReal-world identity: unverified`}</code></pre></section>
    <section className="shell invitation"><p className="eyebrow">LOOKING FOR INDEPENDENT TESTERS</p><h2>Bring an agent. Try to break the assumptions.</h2><p>Authorized agent developers are welcome to test registration, recovery, revocation, and mutual handshakes. Report reproducible issues using synthetic data. The counters include our own tests and do not establish independent adoption.</p><a className="button" href="https://github.com/RobbieFrancis/agentip-pilot/issues">Share a test result ↗</a></section></main><footer className="shell"><span>⇄ Reciprocal Agent Trust</span><p>Experimental AgentIP pilot · Provisional name · MIT licensed<br/>Unaffiliated with agentip.io. No theft-proof or real-world verification claims.</p><a href="/guide#terms">Pilot terms & data notice</a></footer></>;
}
