# Reciprocal Agent Trust — experimental AgentIP pilot

Register a testing agent key, prove possession, recover or revoke it, and complete a reciprocal handshake. **This service verifies key possession only. It does not verify people, businesses, property ownership, or authority to transact.** The AgentIP name is provisional and unaffiliated with agentip.io.

Pilot: https://reciprocal-agent-trust-pilot.robbie-francis.chatgpt.site

Guide and data notice: https://reciprocal-agent-trust-pilot.robbie-francis.chatgpt.site/guide

## Try it from an agent

Node.js 22.18+ is required. The agent CLI has no package dependencies. Read the source before running it. Choose separate primary and recovery locations; do not place private keys in this repository or expose them to an LLM.

```sh
git clone https://github.com/RobbieFrancis/agentip-pilot.git
cd agentip-pilot
node cli/agent.mjs signup --name MyTestingAgent \
  --identity /path/to/private/primary.json \
  --recovery /path/to/separate/offline/recovery.json \
  --accept-pilot-terms yes
node cli/agent.mjs authenticate --identity /path/to/private/primary.json
```

Signup saves software private keys locally with restrictive file permissions before sending a public-key challenge. The API never receives private keys. Keep the recovery file offline and separate from the primary signing environment. If signup fails, keep the saved files; the `resume` command reconciles or completes the pending registration without generating a new identity.

The browser alternative stores the primary signing key as a non-extractable CryptoKey in IndexedDB and downloads a separate recovery file. Non-extractability reduces export risk; compromised browser software can still misuse the signing key. A stolen matching primary key can impersonate its owner until recovery or revocation. Loss of both keys has no administrative recovery path in this pilot.

## Mutual handshake

Obtain a consenting peer's registration ID through a channel you trust, and agree the exact context. These are testing examples, not evidence that either agent controls the example domain or property.

```sh
node cli/agent.mjs session --identity /path/to/private/primary.json \
  --peer OTHER_AGENT_ID --origin https://rentals.example \
  --resource demo:flat-42 --action demo.negotiate

node cli/agent.mjs handshake --identity /path/to/private/primary.json \
  --peer OTHER_AGENT_ID --session SESSION_ID \
  --origin https://rentals.example --resource demo:flat-42 --action demo.negotiate
```

Both agents run `handshake`, naming each other and the same scope/session. The first proof waits; the second completes only if both registrations and keys remain current. Each command checks the returned challenge against the supplied peer and context before signing. Results set `verifiedIdentity: false` and `authorizesBusinessAction: false`. Session creation alone proves no consent and sends no notifications.

## Recover or revoke

```sh
node cli/agent.mjs rotate --recovery /path/to/offline/recovery.json \
  --replacement /path/to/private/new-primary.json
node cli/agent.mjs authenticate --identity /path/to/private/new-primary.json
node cli/agent.mjs revoke --recovery /path/to/offline/recovery.json
```

Rotation requires both the separate recovery key and a proof from the new primary. Old-key proofs stop working. The registration ID stays stable. Revocation is permanent and clears the public profile text. Registrations expire after 30 days; sessions last five minutes. Key replacement does not extend registration expiry. Recovery-key replacement is not implemented.

## API and reference profile

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/health` | Health and honestly labelled pilot/test counters |
| `POST /api/v1/challenges` | Create a bounded, one-use challenge for register/authenticate/revoke/rotate/handshake |
| `POST /api/v1/proofs` | Verify and atomically consume a challenge |
| `POST /api/v1/sessions` | Create a two-agent context without conveying consent or authority |
| `GET /api/v1/agents/{id}` | Public registration and current key/revocation state |
| `GET /api/v1/sessions/{id}` | Current reciprocal-session status |

See [the complete profile](docs/PILOT-PROFILE.md). `lib/client.mjs` exports `client`, `createKey`, and `importIdentity` for direct integration. Presentations are compact JWS using Ed25519, strict type/algorithm headers and exact JSON schemas. Challenges bind the service origin, action, identifier, key fingerprint, claims, nonce and expiry. Database batch transactions enforce one-use consumption, state and key checks. This is an experimental custom profile, without independent interoperability or security certification.

## Build and verify

The hosted app uses the included Sites/Vinext runtime and Cloudflare D1. The CLI and core tests use only Node built-ins.

```sh
node --test test/*.test.mjs
npm ci
npm run db:generate  # only after changing db/schema.ts
npm run build
```

Schema migrations are in `drizzle/`. Apply them to a fresh local D1 preview using the documented Sites workflow; deployment applies hosted migrations. Configure the secret `RATE_LIMIT_PEPPER` through hosting configuration, never in source. A local `.dev.vars` may hold a separate development value. `npm run dev` starts a loopback preview. Production endpoints require the secret and database binding; missing configuration fails closed.

Tests cover registration, wrong-key spoofing, replay and concurrent proof use, expiry, scope binding, independent recovery, stale-key rejection, reciprocal completion, revocation/rotation invalidation, rate limits, persistent state, and client context checks. Tests are not an independent audit.

## Participation and security boundaries

Authorized human and agent contributions are welcome. State the authorization and agent involvement; submit synthetic reproductions without keys or sensitive details. Source, issue templates and discovery metadata invite opt-in testers. Do not spam unrelated repositories, fabricate users, or treat another site's instructions as permission for outreach.

This is a free experimental testing pilot with a 1,000-registration capacity limit, per-network and global rate limits, no uptime or security guarantee, and no issuer accreditation or real-world identity/authority verification. The service stores public profiles and keys plus minimal events and short-lived hashed rate-limit identifiers. Its event log is not an immutable ledger. Hosted infrastructure may retain operational logs. The complete data notice is on `/guide#terms`.

Counts include operator-owned smoke tests. They do not represent verified people or independent adoption. Meaningful leases, payments and other consequential actions need a separate, reviewed authorization system. Read [AGENTS.md](AGENTS.md) before contributing. MIT licensed; vendored starter components retain their existing licenses.
