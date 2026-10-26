# Experimental public profile 0.2

This hosted profile supplements the original local reference. Its assurance is deliberately limited to **registered key possession**. It issues no real-world identity or authority credentials. It is not an implementation of OAuth DPoP, W3C VC, DID, or a registered AgentIP standard.

Clients generate distinct primary and recovery Ed25519 key pairs. Private keys never enter service requests. The browser stores the primary CryptoKey as non-extractable in IndexedDB and downloads an exportable recovery key for separate storage. CLI keys are software keys stored in user-chosen files with mode 0600. A compromised signing environment can still misuse a non-extractable key; recovery only remains independent if the recovery file is kept elsewhere.

## Registration

POST `/api/v1/challenges` with `action: "register"`, a client-generated `agentId` (`agt_` plus UUIDv4), public JWKs in `publicKey` and `recoveryPublicKey`, `profile: {name, description}`, and `acceptPilotTerms: true`. Public JWKs contain exactly `kty: "OKP"`, `crv: "Ed25519"`, `x`. No `d` or unknown members are allowed. Name/description are self-declared and public to anyone with the agent ID. They establish no identity claim.

The service returns a stored challenge with kind/version, random ID and 256-bit nonce, origin, action, agent ID, RFC 7638 signer fingerprint, exact claims, issuedAt and expiresAt. Clients must check the origin, action, identifier, signer fingerprint and claims before signing. Challenge validity is two minutes. A challenge alone does not authorize any write.

POST `/api/v1/proofs` with `proof`, a compact JWS. Protected headers are exactly `{alg: "Ed25519", typ: "agentip-pilot-proof+jwt"}`. Payload fields are exactly `{kind: "agentip-pilot-proof", version: "0.2", isAgent: true, challenge, publicKey}`. Signature covers the original encoded header and payload, with no padding. The server checks the public key against its stored expected key and compares the full signed challenge to the stored copy. It refuses unexpected fields, wrong algorithms/types, malformed encodings, mismatched keys/context, expiry and replay. The JSON parser uses JavaScript last-member-wins semantics; clients must emit unique members. Interoperability with other implementations remains untested.

Challenges are consumed using a conditional database update inside a D1 batch transaction. All state-changing statements are conditional on that attempt's consumption marker. Agent primary-key equality, active state, and relevant session state are rechecked in SQL for state changes. A competing submission cannot reuse the consumed challenge. Public/recovery keys have unique constraints. The pilot has a maximum of 1,000 total registrations and bounded challenge/session issuance rates.

## Authentication, revocation and rotation

Authentication challenges use `{action: "authenticate", agentId}`. The stored primary key must sign. A successful response is an informational local API result, not a transferable authorization token.

Revocation challenges use `{action: "revoke", agentId, useRecovery: boolean}` and require either the current primary or the registered recovery key, selected explicitly. Revocation clears the profile and rejects future authentication and handshake proofs. Stale, unconsumed challenges are checked against current registration state at use time.

Rotation challenges use `{action: "rotate", agentId, newPublicKey}`. The existing recovery key signs `proof`; the new primary key signs `newKeyProof` over the identical stored challenge. The primary key cannot rotate itself without recovery authority. The registration ID remains stable; old proofs are rejected after rotation. Recovery-key replacement and account recovery after loss of both keys are intentionally absent in this pilot.

Registrations expire after 30 days. There is no renewal endpoint in this version. Expired records remain inert to prevent identifier/key reuse; operators may close new enrollment at the pilot capacity limit.

## Reciprocal sessions

POST `/api/v1/sessions` with two distinct active IDs (`initiatorId`, `peerId`) and `scope: {origin, resource, action}`. Session creation is rate limited but does not require a proof: it creates no messages, notifications or authorization. It is not evidence that either party agreed. Context origins must be exact canonical HTTPS origins. The service does not fetch those origins or assert control of them.

Both parties obtain `{action: "handshake", agentId, sessionId}` challenges, inspect the participants and scope, and submit their signed proofs. A first proof leaves `waiting_for_peer`. The completion update checks both current primary keys, confirmations, registration expiry/revocation and session expiry in the same transaction. Rotated keys invalidate earlier confirmations. A completed result states only that both registered keys signed the context. It explicitly sets `verifiedIdentity: false` and `authorizesBusinessAction: false`.

GET `/api/v1/sessions/{id}` recalculates current state rather than treating a past completion as permanent authority. Revocation invalidates a completed session. Sessions last five minutes and are deleted during later challenge cleanup. Applications must not cache a completion as continuing authorization.

## Storage and abuse limits

Cloudflare D1 stores public profiles/keys, challenges, sessions, confirmations, minimal events and rate counters. No server signing credential or user private key is stored. Network identifiers are hashed using a server-secret pepper and daily epoch; raw addresses are not stored by application tables. Rate counters expire within two windows (20 minutes); expired rows are removed on later challenges. Rate limiting keys use the platform's trusted network header. An upstream network change or proxy can affect per-network limits; global quotas and enrollment capacity also apply.

Events are kept up to 30 days with cleanup during later challenges. Agent records persist until operator cleanup; revocation removes profile text but retains keys and status. Hosting infrastructure has its own operational logs. This event store is not an immutable audit ledger and has no external integrity checkpoint.

The service requires HTTPS, explicit browser-origin matching, a bounded JSON body and fixed allowed operations. CLI clients reject redirects and require expected challenge context. The public service is not independently audited and is unsuitable for consequential contracts, payments, identity screening or security accreditation.
