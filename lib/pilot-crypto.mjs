export const PROOF_TYPE = 'agentip-pilot-proof+jwt';
export class PilotError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
export function ensure(value, code = 'invalid_request', status = 400) { if (!value) throw new PilotError(status, code); }
export function exact(value, keys) {
  ensure(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join() === [...keys].sort().join(), 'invalid_schema');
}
export function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  ensure(value && typeof value === 'object', 'invalid_json');
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}
export function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); }
export function unb64(value) {
  ensure(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value), 'invalid_encoding');
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
  ensure(b64(bytes) === value, 'invalid_encoding'); return bytes;
}
export function publicKey(value) {
  exact(value, ['crv', 'kty', 'x']);
  ensure(value.kty === 'OKP' && value.crv === 'Ed25519' && typeof value.x === 'string' && value.x.length === 43 && unb64(value.x).length === 32, 'invalid_public_key');
  return { crv: value.crv, kty: value.kty, x: value.x };
}
export async function hash(value) { return b64(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))); }
export async function fingerprint(value) { return hash(canonical(publicKey(value))); }
export async function signProof(key, jwk, challenge) {
  const header = b64(new TextEncoder().encode(JSON.stringify({ alg: 'Ed25519', typ: PROOF_TYPE })));
  const payload = b64(new TextEncoder().encode(JSON.stringify({ kind: 'agentip-pilot-proof', version: '0.2', isAgent: true, challenge, publicKey: publicKey(jwk) })));
  const input = header + '.' + payload;
  const signature = await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(input));
  return input + '.' + b64(signature);
}
export async function checkProof(token, expectedKey, expectedChallenge) {
  ensure(typeof token === 'string' && token.length <= 24576, 'invalid_proof');
  const parts = token.split('.'); ensure(parts.length === 3, 'invalid_proof');
  let header, payload, signature;
  try {
    header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(unb64(parts[0])));
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(unb64(parts[1])));
    signature = unb64(parts[2]);
  } catch { throw new PilotError(400, 'invalid_proof'); }
  exact(header, ['alg', 'typ']); ensure(header.alg === 'Ed25519' && header.typ === PROOF_TYPE, 'unsupported_header');
  exact(payload, ['kind', 'version', 'isAgent', 'challenge', 'publicKey']);
  ensure(payload.kind === 'agentip-pilot-proof' && payload.version === '0.2' && payload.isAgent === true, 'agent_disclosure_required');
  publicKey(payload.publicKey);
  ensure(canonical(payload.publicKey) === canonical(expectedKey), 'wrong_signing_key', 401);
  ensure(canonical(payload.challenge) === canonical(expectedChallenge), 'challenge_binding_mismatch', 401);
  ensure(signature.length === 64, 'invalid_signature', 401);
  const key = await crypto.subtle.importKey('jwk', expectedKey, 'Ed25519', false, ['verify']);
  ensure(await crypto.subtle.verify('Ed25519', key, signature, new TextEncoder().encode(parts[0] + '.' + parts[1])), 'invalid_signature', 401);
  return payload;
}
export function readProofChallenge(token) {
  ensure(typeof token === 'string' && token.length <= 24576 && token.split('.').length === 3, 'invalid_proof');
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(unb64(token.split('.')[1]))).challenge; }
  catch { throw new PilotError(400, 'invalid_proof'); }
}
