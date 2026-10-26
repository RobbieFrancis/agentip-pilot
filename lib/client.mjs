import { canonical, signProof, fingerprint } from './pilot-crypto.mjs';
export async function createKey(extractable = true) {
  const pair = await crypto.subtle.generateKey('Ed25519', extractable, ['sign', 'verify']);
  const { kty, crv, x } = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { publicKey: { kty, crv, x }, privateKey: pair.privateKey };
}
export async function importIdentity(value) {
  return { publicKey: value.publicKey, privateKey: await crypto.subtle.importKey('jwk', value.privateJwk, 'Ed25519', false, ['sign']) };
}
export function client(server, fetcher = fetch) {
  const origin = new URL(server).origin;
  if (new URL(server).protocol !== 'https:' && !['127.0.0.1', 'localhost'].includes(new URL(server).hostname)) throw new Error('HTTPS required');
  const call = async (path, value) => {
    const response = await fetcher(origin + '/api/v1' + path, value === undefined ? { redirect: 'error' } : { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) });
    const result = await response.json(); if (!response.ok) throw new Error(result.error ?? 'Service request failed'); return result;
  };
  const prove = async (input, identity, newIdentity, review) => {
    const { challenge } = await call('/challenges', input);
    if (challenge.origin !== origin || challenge.agentId !== input.agentId || challenge.action !== input.action || challenge.signerFingerprint !== await fingerprint(identity.publicKey)) throw new Error('Unexpected challenge binding');
    if (input.action === 'register' && (canonical(challenge.claims.publicKey) !== canonical(input.publicKey) || canonical(challenge.claims.recoveryPublicKey) !== canonical(input.recoveryPublicKey) || canonical(challenge.claims.profile) !== canonical(input.profile))) throw new Error('Registration claims changed');
    if (input.action === 'rotate' && canonical(challenge.claims.newPublicKey) !== canonical(newIdentity?.publicKey)) throw new Error('Replacement key changed');
    if (input.action === 'handshake') {
      if (!review) throw new Error('Explicit handshake-context review required');
      if (challenge.claims.sessionId !== input.sessionId || !await review(challenge.claims)) throw new Error('Handshake context refused');
    }
    const proof = await signProof(identity.privateKey, identity.publicKey, challenge);
    return call('/proofs', newIdentity ? { proof, newKeyProof: await signProof(newIdentity.privateKey, newIdentity.publicKey, challenge) } : { proof });
  };
  return { call, prove };
}
